local args = {...}
local infile = args[1] or "ByteCode.luac"
local outfile = args[2] or "DecompiledOutput.lua"

local function rshift(n, bits) return math.floor(n / 2 ^ bits) end
local function band(a, b)
    local p, c = 1, 0
    while a > 0 and b > 0 do
        local ra, rb = a % 2, b % 2
        if ra + rb > 1 then c = c + p end
        a, b, p = (a - ra) / 2, (b - rb) / 2, p * 2
    end
    return c
end
local function get_bits(num, start, count) return band(rshift(num, start), 2 ^ count - 1) end
local function escape_str(s)
    local res = string.format("%q", s)
    return res:gsub("\\\n", "\\n"):gsub("\r", "\\r")
end
local function is_ident(str)
    return type(str) == "string" and str:match("^[%a_][%w_]*$")
end

local OP = {
    MOVE=0, LOADK=1, LOADBOOL=2, LOADNIL=3, GETUPVAL=4, GETGLOBAL=5,
    GETTABLE=6, SETGLOBAL=7, SETUPVAL=8, SETTABLE=9, NEWTABLE=10, SELF=11,
    ADD=12, SUB=13, MUL=14, DIV=15, MOD=16, POW=17, UNM=18, NOT=19,
    LEN=20, CONCAT=21, JMP=22, EQ=23, LT=24, LE=25, TEST=26, TESTSET=27,
    CALL=28, TAILCALL=29, RETURN=30, FORLOOP=31, FORPREP=32, TFORLOOP=33,
    SETLIST=34, CLOSE=35, CLOSURE=36, VARARG=37
}
local OP_NAME = {}; for k,v in pairs(OP) do OP_NAME[v] = k end

local Reader = {data="",pos=1,little_endian=true,int_size=4,size_t_size=8,instr_size=4,num_size=8}
function Reader:new(data) return setmetatable({data=data,pos=1},{__index=self}) end
function Reader:byte()
    if self.pos > #self.data then return 0 end
    local b = string.byte(self.data, self.pos); self.pos = self.pos + 1; return b
end
function Reader:bytes(n) local t={}; for i=1,n do t[i]=self:byte() end; return t end
function Reader:int_from_bytes(bytes)
    local sum = 0
    if self.little_endian then for i=1,#bytes do sum = sum + bytes[i]*(2^((i-1)*8)) end
    else for i=1,#bytes do sum = sum + bytes[i]*(2^((#bytes-i)*8)) end end
    return sum
end
function Reader:int() return self:int_from_bytes(self:bytes(self.int_size)) end
function Reader:size_t() return self:int_from_bytes(self:bytes(self.size_t_size)) end
function Reader:instruction() return self:int_from_bytes(self:bytes(self.instr_size)) end
function Reader:double()
    local b = self:bytes(8)
    if not self.little_endian then local t={}; for i=8,1,-1 do t[9-i]=b[i] end; b=t end
    local sign = (b[8]>127) and -1 or 1
    local exp = band(b[8],127)*16 + rshift(b[7],4)
    local mant = band(b[7],15)
    for i=6,1,-1 do mant = mant*256 + b[i] end
    if exp==0 then return (mant==0) and 0 or sign*mant*2^(-1022-52)
    elseif exp==2047 then return (mant==0) and sign*(1/0) or 0/0 end
    return sign*(1+mant/(2^52))*(2^(exp-1023))
end
function Reader:string()
    local len = self:size_t(); if len==0 then return nil end
    local str = string.sub(self.data, self.pos, self.pos+len-2)
    self.pos = self.pos + len; return str
end

local function decode_instr(raw)
    return {
        op=get_bits(raw,0,6), a=get_bits(raw,6,8), c=get_bits(raw,14,9),
        b=get_bits(raw,23,9), bx=get_bits(raw,14,18), sbx=get_bits(raw,14,18)-131071
    }
end

local func_id = 0
local function parse_header(r)
    if string.sub(r.data,1,4) ~= "\27Lua" then io.stderr:write("Warning: Invalid signature\n") end
    r.pos=5; r:byte(); r:byte(); r.little_endian=(r:byte()==1)
    r.int_size=r:byte(); r.size_t_size=r:byte(); r.instr_size=r:byte(); r.num_size=r:byte(); r:byte()
end

local function parse_function(r, parent)
    local f = {source=r:string(), line_start=r:int(), line_end=r:int(), nups=r:byte(),
               nparams=r:byte(), is_vararg=r:byte(), maxstack=r:byte(), id=func_id, parent=parent}
    func_id = func_id + 1
    local n = r:int(); f.code = {}; for i=1,n do f.code[i] = decode_instr(r:instruction()) end
    n = r:int(); f.constants = {}
    for i=0,n-1 do
        local t = r:byte()
        if t==1 then f.constants[i]={type="bool",value=r:byte()~=0}
        elseif t==3 then f.constants[i]={type="number",value=r:double()}
        elseif t==4 then f.constants[i]={type="string",value=r:string()}
        else f.constants[i]={type="nil"} end
    end
    n = r:int(); f.protos = {}; for i=0,n-1 do f.protos[i] = parse_function(r, f) end
    n = r:int(); for i=1,n do r:int() end
    n = r:int(); f.locals = {}; for i=1,n do f.locals[i]={name=r:string(),startpc=r:int(),endpc=r:int()} end
    n = r:int(); f.upvalues = {}; for i=1,n do f.upvalues[i] = r:string() end
    return f
end

local function analyze_upvalues(func)
    local bindings = {}
    local code = func.code
    for pc=1,#code do
        local instr = code[pc]
        if instr.op == OP.CLOSURE then
            local proto_idx = instr.bx
            local proto = func.protos[proto_idx]
            bindings[proto_idx] = {}
            for i=1,proto.nups do
                local uv = code[pc+i]
                if uv then
                    if uv.op == OP.MOVE then
                        bindings[proto_idx][i-1] = {type="local", reg=uv.b}
                    elseif uv.op == OP.GETUPVAL then
                        bindings[proto_idx][i-1] = {type="upvalue", index=uv.b}
                    end
                end
            end
        end
    end
    return bindings
end

local function analyze_uses(func)
    local uses = {read_count={}, read_pcs={}, write_pc={}}
    for i=0,func.maxstack do uses.read_count[i]=0; uses.read_pcs[i]={} end
    local code = func.code
    for pc=1,#code do
        local ins = code[pc]
        local op,a,b,c = ins.op, ins.a, ins.b, ins.c
        local function wr(r) uses.write_pc[r]=pc; uses.read_count[r]=0; uses.read_pcs[r]={} end
        local function rd(r) uses.read_count[r]=(uses.read_count[r] or 0)+1; table.insert(uses.read_pcs[r] or {}, pc) end
        
        if op==OP.MOVE then rd(b); wr(a)
        elseif op==OP.LOADK or op==OP.LOADBOOL or op==OP.GETGLOBAL or op==OP.NEWTABLE then wr(a)
        elseif op==OP.LOADNIL then for i=a,b do wr(i) end
        elseif op==OP.GETUPVAL then wr(a)
        elseif op==OP.GETTABLE then rd(b); if c<256 then rd(c) end; wr(a)
        elseif op==OP.SETGLOBAL or op==OP.SETUPVAL then rd(a)
        elseif op==OP.SETTABLE then rd(a); if b<256 then rd(b) end; if c<256 then rd(c) end
        elseif op==OP.SELF then rd(b); wr(a); wr(a+1)
        elseif op>=OP.ADD and op<=OP.POW then if b<256 then rd(b) end; if c<256 then rd(c) end; wr(a)
        elseif op==OP.UNM or op==OP.NOT or op==OP.LEN then rd(b); wr(a)
        elseif op==OP.CONCAT then for i=b,c do rd(i) end; wr(a)
        elseif op==OP.EQ or op==OP.LT or op==OP.LE then if b<256 then rd(b) end; if c<256 then rd(c) end
        elseif op==OP.TEST then rd(a)
        elseif op==OP.TESTSET then rd(b); wr(a)
        elseif op==OP.CALL then
            rd(a); if ins.b>1 then for i=a+1,a+ins.b-1 do rd(i) end end
            if ins.c>=2 then for i=a,a+ins.c-2 do wr(i) end elseif ins.c==0 then wr(a) end
        elseif op==OP.TAILCALL then rd(a); if ins.b>1 then for i=a+1,a+ins.b-1 do rd(i) end end
        elseif op==OP.RETURN then if ins.b>=2 then for i=a,a+ins.b-2 do rd(i) end end
        elseif op==OP.CLOSURE then wr(a)
        elseif op==OP.VARARG then if ins.b>1 then for i=a,a+ins.b-2 do wr(i) end else wr(a) end
        elseif op==OP.SETLIST then rd(a); for i=1,ins.b do rd(a+i) end
        end
    end
    uses.single_use = {}
    for r,c in pairs(uses.read_count) do uses.single_use[r] = (c==1) end
    return uses
end

local function reg(i,fid) return "r"..i.."_"..fid end
local function const_str(k)
    if k.type=="string" then return escape_str(k.value)
    elseif k.type=="nil" then return "nil"
    elseif k.type=="bool" then return tostring(k.value)
    else return tostring(k.value) end
end

local decompile_func

local function create_ctx(func, parent_ctx)
    return {
        func=func, parent=parent_ctx,
        upval_bindings = analyze_upvalues(func),
        uses = analyze_uses(func),
        regs={}, reg_names={}, declared={}, self_info=nil, tables={}, pending_closures={},
        indent=0, statements={}
    }
end

local function ind(ctx) return string.rep("  ", ctx.indent) end
local function emit(ctx, s) table.insert(ctx.statements, ind(ctx)..s) end

local function get_reg_name(ctx, i) return ctx.reg_names[i] or reg(i, ctx.func.id) end
local function get_expr(ctx, i) return ctx.regs[i] or get_reg_name(ctx, i) end
local function set_expr(ctx, i, e) ctx.regs[i] = e end

local function get_rk(ctx, i)
    if i>=256 then return const_str(ctx.func.constants[i-256])
    else return get_expr(ctx, i) end
end

local function resolve_upval(ctx, idx)
    if not ctx.parent then return "upval_"..idx end
    local pf = ctx.parent.func
    local pi = nil
    for i,p in pairs(pf.protos) do if p==ctx.func then pi=i; break end end
    if pi and ctx.parent.upval_bindings[pi] then
        local b = ctx.parent.upval_bindings[pi][idx]
        if b then
            if b.type=="local" then return get_reg_name(ctx.parent, b.reg)
            elseif b.type=="upvalue" then return resolve_upval(ctx.parent, b.index) end
        end
    end
    return "upval_"..idx
end

local function build_table(ctx, i, indent_level)
    local t = ctx.tables[i]
    if not t or (#t.entries==0 and #t.array==0) then return "{}" end
    local parts = {}
    for _,v in ipairs(t.array) do table.insert(parts, v) end
    for _,e in ipairs(t.entries) do
        if e.key_safe then table.insert(parts, e.key.." = "..e.val)
        else table.insert(parts, "["..e.key.."] = "..e.val) end
    end
    if #parts==0 then return "{}" end
    if #parts>2 or t.has_func then
        local ii = string.rep("  ", indent_level+1)
        local ci = string.rep("  ", indent_level)
        return "{\n"..ii..table.concat(parts,",\n"..ii)..",\n"..ci.."}"
    end
    return "{ "..table.concat(parts,", ").." }"
end

local function can_inline(ctx, target_reg)
    local u = ctx.uses
    if not u.single_use[target_reg] then return false end
    local rp = u.read_pcs[target_reg]
    if not rp or #rp~=1 then return false end
    local use_op = ctx.func.code[rp[1]].op
    return use_op==OP.CALL or use_op==OP.SETTABLE
end

local function decompile_inline(ctx, proto, indent_level)
    local params = {}
    for i=0,proto.nparams-1 do table.insert(params, reg(i, proto.id)) end
    if proto.is_vararg~=0 then table.insert(params, "...") end
    
    local child = create_ctx(proto, ctx)
    child.indent = 0
    decompile_func(child, proto)
    
    local lines = {"function("..table.concat(params,", ")..")"}
    table.insert(lines, "  -- line: ["..proto.line_start..", "..proto.line_end.."] id: "..proto.id)
    for _,s in ipairs(child.statements) do table.insert(lines, "  "..s) end
    table.insert(lines, "end")
    return table.concat(lines, "\n"..string.rep("  ", indent_level))
end

function decompile_func(ctx, func)
    local code = func.code
    local n = #code
    local pc = 1
    
    while pc <= n do
        local ins = code[pc]
        local op,a,b,c = ins.op, ins.a, ins.b, ins.c
        local bx, sbx = ins.bx, ins.sbx
        
        if op==OP.MOVE then set_expr(ctx, a, get_expr(ctx, b))
        elseif op==OP.LOADK then set_expr(ctx, a, const_str(func.constants[bx]))
        elseif op==OP.LOADBOOL then set_expr(ctx, a, b~=0 and "true" or "false"); if c~=0 then pc=pc+1 end
        elseif op==OP.LOADNIL then for i=a,b do set_expr(ctx, i, "nil") end
        elseif op==OP.GETUPVAL then set_expr(ctx, a, resolve_upval(ctx, b))
        elseif op==OP.GETGLOBAL then set_expr(ctx, a, func.constants[bx].value)
        elseif op==OP.GETTABLE then
            local obj = get_expr(ctx, b)
            local key = get_rk(ctx, c)
            if c>=256 then
                local kc = func.constants[c-256]
                if kc.type=="string" and is_ident(kc.value) then
                    set_expr(ctx, a, obj.."."..kc.value)
                else set_expr(ctx, a, obj.."["..key.."]") end
            else set_expr(ctx, a, obj.."["..key.."]") end
        elseif op==OP.SETGLOBAL then emit(ctx, func.constants[bx].value.." = "..get_expr(ctx, a))
        elseif op==OP.SETUPVAL then emit(ctx, resolve_upval(ctx, b).." = "..get_expr(ctx, a))
        elseif op==OP.SETTABLE then
            local key = get_rk(ctx, b)
            local val = c<256 and ctx.pending_closures[c] or nil
            if not val then val = get_rk(ctx, c) end
            if c<256 then ctx.pending_closures[c] = nil end
            
            if ctx.tables[a] then
                local ks = false; local kn = key
                if b>=256 then
                    local kc = func.constants[b-256]
                    if kc.type=="string" and is_ident(kc.value) then ks=true; kn=kc.value end
                end
                if val:match("^function%(") then ctx.tables[a].has_func=true end
                table.insert(ctx.tables[a].entries, {key=kn, val=val, key_safe=ks})
            else
                local obj = get_expr(ctx, a)
                local target
                if b>=256 then
                    local kc = func.constants[b-256]
                    if kc.type=="string" and is_ident(kc.value) then target=obj.."."..kc.value
                    else target=obj.."["..key.."]" end
                else target=obj.."["..key.."]" end
                emit(ctx, target.." = "..val)
            end
        elseif op==OP.NEWTABLE then ctx.tables[a]={entries={},array={},has_func=false}; set_expr(ctx,a,nil)
        elseif op==OP.SELF then
            local obj = get_expr(ctx, b)
            local mn = nil
            if c>=256 then local kc=func.constants[c-256]; if kc.type=="string" then mn=kc.value end end
            ctx.self_info = {obj=obj, method=mn, method_raw=get_rk(ctx,c)}
            set_expr(ctx, a+1, obj)
            if mn and is_ident(mn) then set_expr(ctx, a, obj..":"..mn)
            else set_expr(ctx, a, obj.."["..ctx.self_info.method_raw.."]") end
        elseif op>=OP.ADD and op<=OP.POW then
            local ops={[OP.ADD]="+",[OP.SUB]="-",[OP.MUL]="*",[OP.DIV]="/",[OP.MOD]="%",[OP.POW]="^"}
            set_expr(ctx, a, get_rk(ctx,b).." "..ops[op].." "..get_rk(ctx,c))
        elseif op==OP.UNM then set_expr(ctx, a, "-"..get_expr(ctx,b))
        elseif op==OP.NOT then set_expr(ctx, a, "not "..get_expr(ctx,b))
        elseif op==OP.LEN then set_expr(ctx, a, "#"..get_expr(ctx,b))
        elseif op==OP.CONCAT then
            local p={}; for i=b,c do table.insert(p, get_expr(ctx,i)) end
            set_expr(ctx, a, table.concat(p," .. "))
        elseif op==OP.JMP then
        elseif op==OP.EQ then
            local cmp = (a~=0) and "~=" or "=="
            emit(ctx, "if "..get_rk(ctx,b).." "..cmp.." "..get_rk(ctx,c).." then")
            ctx.indent = ctx.indent + 1
        elseif op==OP.LT then
            local cmp = (a~=0) and ">=" or "<"
            emit(ctx, "if "..get_rk(ctx,b).." "..cmp.." "..get_rk(ctx,c).." then")
            ctx.indent = ctx.indent + 1
        elseif op==OP.LE then
            local cmp = (a~=0) and ">" or "<="
            emit(ctx, "if "..get_rk(ctx,b).." "..cmp.." "..get_rk(ctx,c).." then")
            ctx.indent = ctx.indent + 1
        elseif op==OP.TEST then
            local cond = (c==0) and "not "..get_expr(ctx,a) or get_expr(ctx,a)
            emit(ctx, "if "..cond.." then")
            ctx.indent = ctx.indent + 1
        elseif op==OP.TESTSET then
            local cond = (c==0) and "not "..get_expr(ctx,b) or get_expr(ctx,b)
            emit(ctx, "if "..cond.." then "..get_reg_name(ctx,a).." = "..get_expr(ctx,b).." end")
        elseif op==OP.CALL then
            local fe; local args={}
            if ctx.self_info then
                local si = ctx.self_info
                if si.method and is_ident(si.method) then fe=si.obj..":"..si.method
                else fe=si.obj.."["..si.method_raw.."]" end
                if b>2 then for i=a+2,a+b-1 do
                    local ae = get_expr(ctx,i)
                    if ctx.tables[i] then ae=build_table(ctx,i,ctx.indent); ctx.tables[i]=nil end
                    if ctx.pending_closures[i] then ae=ctx.pending_closures[i]; ctx.pending_closures[i]=nil end
                    table.insert(args, ae)
                end end
                ctx.self_info = nil
            else
                fe = get_expr(ctx, a)
                if b>1 then for i=a+1,a+b-1 do
                    local ae = get_expr(ctx,i)
                    if ctx.tables[i] then ae=build_table(ctx,i,ctx.indent); ctx.tables[i]=nil end
                    if ctx.pending_closures[i] then ae=ctx.pending_closures[i]; ctx.pending_closures[i]=nil end
                    table.insert(args, ae)
                end end
            end
            local call = fe.."("..table.concat(args,", ")..")"
            if c==0 then emit(ctx, call); set_expr(ctx,a,call)
            elseif c==1 then emit(ctx, call)
            elseif c==2 then
                local rn = get_reg_name(ctx,a)
                if not ctx.declared[a] then ctx.declared[a]=true; emit(ctx, "local "..rn.." = "..call)
                else emit(ctx, rn.." = "..call) end
                set_expr(ctx,a,rn); ctx.reg_names[a]=rn
            else
                local rets={}
                for i=a,a+c-2 do local rn=get_reg_name(ctx,i); table.insert(rets,rn); ctx.declared[i]=true; set_expr(ctx,i,rn); ctx.reg_names[i]=rn end
                emit(ctx, "local "..table.concat(rets,", ").." = "..call)
            end
        elseif op==OP.TAILCALL then
            local fe = get_expr(ctx,a); local args={}
            if b>1 then for i=a+1,a+b-1 do table.insert(args, get_expr(ctx,i)) end end
            emit(ctx, "return "..fe.."("..table.concat(args,", ")..")")
        elseif op==OP.RETURN then
            if b==1 then emit(ctx, "return")
            elseif b==2 then emit(ctx, "return "..get_expr(ctx,a))
            else local rets={}; for i=a,a+b-2 do table.insert(rets, get_expr(ctx,i)) end
                emit(ctx, "return "..table.concat(rets,", ")) end
        elseif op==OP.FORLOOP then
            ctx.indent = math.max(0, ctx.indent-1)
            emit(ctx, "end")
        elseif op==OP.FORPREP then
            emit(ctx, "for "..get_reg_name(ctx,a+3).." = "..get_expr(ctx,a)..", "..get_expr(ctx,a+1)..", "..get_expr(ctx,a+2).." do")
            ctx.indent = ctx.indent + 1; ctx.declared[a+3]=true
        elseif op==OP.TFORLOOP then
            local vars={}
            for i=a+3,a+2+c do table.insert(vars, get_reg_name(ctx,i)); ctx.declared[i]=true end
            emit(ctx, "for "..table.concat(vars,", ").." in "..get_expr(ctx,a).." do")
            ctx.indent = ctx.indent + 1
        elseif op==OP.SETLIST then
            if ctx.tables[a] then for i=1,b do table.insert(ctx.tables[a].array, get_expr(ctx,a+i)) end end
        elseif op==OP.CLOSE then emit(ctx, "-- close: "..get_reg_name(ctx,a))
        elseif op==OP.CLOSURE then
            local proto = func.protos[bx]
            local params={}
            for i=0,proto.nparams-1 do table.insert(params, reg(i,proto.id)) end
            if proto.is_vararg~=0 then table.insert(params, "...") end
            
            if can_inline(ctx, a) then
                local ic = decompile_inline(ctx, proto, ctx.indent)
                ctx.pending_closures[a] = ic
                set_expr(ctx, a, ic)
            else
                local next_ins = code[pc+1]
                local is_named = next_ins and next_ins.op==OP.SETGLOBAL
                local fn = is_named and func.constants[next_ins.bx].value or nil
                
                if is_named then emit(ctx, "function "..fn.."("..table.concat(params,", ")..")")
                else emit(ctx, "local "..get_reg_name(ctx,a).." = function("..table.concat(params,", ")..")"); ctx.declared[a]=true end
                
                emit(ctx, "  -- line: ["..proto.line_start..", "..proto.line_end.."] id: "..proto.id)
                
                local child = create_ctx(proto, ctx)
                child.indent = ctx.indent + 1
                decompile_func(child, proto)
                for _,s in ipairs(child.statements) do table.insert(ctx.statements, s) end
                
                emit(ctx, "end")
                set_expr(ctx, a, get_reg_name(ctx,a))
                if is_named then pc=pc+1 end
            end
            pc = pc + proto.nups
        elseif op==OP.VARARG then
            if b==0 then set_expr(ctx,a,"...")
            else local vars={}; for i=a,a+b-2 do table.insert(vars,get_reg_name(ctx,i)); ctx.declared[i]=true end
                emit(ctx, "local "..table.concat(vars,", ").." = ...") end
        else emit(ctx, "-- UNKNOWN OP: "..(OP_NAME[op] or op))
        end
        
        pc = pc + 1
    end
end

local f = io.open(infile, "rb")
if not f then io.stderr:write("Error: Cannot open "..infile.."\n"); os.exit(1) end
local data = f:read("*a"); f:close()

print("Decompiling: "..infile)
print("  - Analyzing upvalues")
print("  - Analyzing register usage")
print("  - Generating output")

local reader = Reader:new(data)
parse_header(reader)
local main = parse_function(reader, nil)

local ctx = create_ctx(main, nil)
table.insert(ctx.statements, "-- filename: "..(main.source or ""))
table.insert(ctx.statements, "-- version: lua51")
table.insert(ctx.statements, "-- line: ["..main.line_start..", "..main.line_end.."] id: "..main.id)

decompile_func(ctx, main)

local out = io.open(outfile, "w")
for _,line in ipairs(ctx.statements) do out:write(line.."\n") end
out:close()

print("Output saved to: "..outfile)