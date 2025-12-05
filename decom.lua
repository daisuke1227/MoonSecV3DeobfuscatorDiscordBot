local infile = arg[1] or "ByteCode.luac"
local outfile = arg[2] or "DecompiledOutput.lua"
local function rshift(n, bits)
	return math.floor(n / 2 ^ bits)
end;
local function band(a, b)
	local p, c = 1, 0;
	while a > 0 and b > 0 do
		local ra, rb = a % 2, b % 2;
		if ra + rb > 1 then
			c = c + p
		end;
		a, b, p = (a - ra) / 2, (b - rb) / 2, p * 2
	end;
	return c
end;
local OP = {
	MOVE = 0,
	LOADK = 1,
	LOADBOOL = 2,
	LOADNIL = 3,
	GETUPVAL = 4,
	GETGLOBAL = 5,
	GETTABLE = 6,
	SETGLOBAL = 7,
	SETUPVAL = 8,
	SETTABLE = 9,
	NEWTABLE = 10,
	SELF = 11,
	ADD = 12,
	SUB = 13,
	MUL = 14,
	DIV = 15,
	MOD = 16,
	POW = 17,
	UNM = 18,
	NOT = 19,
	LEN = 20,
	CONCAT = 21,
	JMP = 22,
	EQ = 23,
	LT = 24,
	LE = 25,
	TEST = 26,
	TESTSET = 27,
	CALL = 28,
	TAILCALL = 29,
	RETURN = 30,
	FORLOOP = 31,
	FORPREP = 32,
	TFORLOOP = 33,
	SETLIST = 34,
	CLOSE = 35,
	CLOSURE = 36,
	VARARG = 37
}
local OP_NAME = {}
for k, v in pairs(OP) do
	OP_NAME[v] = k
end;
local Reader = {
	data = "",
	pos = 1,
	little_endian = true,
	int_size = 4,
	size_t_size = 4
}
Reader.__index = Reader;
function Reader:new(data)
	local r = setmetatable({
		data = data,
		pos = 1
	}, Reader)
	return r
end;
function Reader:byte()
	local b = self.data:byte(self.pos)
	self.pos = self.pos + 1;
	return b
end;
function Reader:bytes(n)
	local t = {}
	for i = 1, n do
		local b = self:byte()
		if not b then
			return nil
		end;
		table.insert(t, b)
	end;
	return t
end;
function Reader:read_int(sz)
	local bytes = self:bytes(sz)
	if not bytes then
		return nil
	end;
	local sum = 0;
	if self.little_endian then
		for i = 1, sz do
			sum = sum + bytes[i] * (2 ^ ((i - 1) * 8))
		end
	else
		for i = 1, sz do
			sum = sum + bytes[i] * (2 ^ ((sz - i) * 8))
		end
	end;
	return sum
end;
function Reader:int()
	return self:read_int(self.int_size)
end;
function Reader:size_t()
	return self:read_int(self.size_t_size)
end;
function Reader:number()
	local b = self:bytes(8)
	if not b then
		return 0
	end;
	if not self.little_endian then
		local t = {}
		for i = 8, 1, -1 do
			t[9 - i] = b[i]
		end;
		b = t
	end;
	local sign = (b[8] > 127) and -1 or 1;
	local exp = band(b[8], 127) * 16 + rshift(b[7], 4)
	local mant = band(b[7], 15)
	for i = 6, 1, -1 do
		mant = mant * 256 + b[i]
	end;
	if exp == 0 then
		return (mant == 0) and 0 or sign * mant * 3.4175792574734563e-227
	elseif exp == 2047 then
		return (mant == 0) and sign * (1 / 0) or 0 / 0
	end;
	return sign * (1 + mant / (2 ^ 52)) * (2 ^ (exp - 1023))
end;
function Reader:string()
	local len = self:size_t()
	if not len or len == 0 then
		return nil
	end;
	local s = self.data:sub(self.pos, self.pos + len - 2)
	self.pos = self.pos + len;
	return s
end;
local function parse_header(r)
	assert(r:byte() == 27 and r:byte() == 76 and r:byte() == 117 and r:byte() == 97, "Not a Lua bytecode file")
	local version = r:byte()
	local format = r:byte()
	local endian = r:byte()
	r.little_endian = (endian == 1)
	r.int_size = r:byte()
	r.size_t_size = r:byte()
	local instr_size = r:byte()
	local number_size = r:byte()
	local integral = r:byte()
end;
local proto_id = 0;
local function parse_function(r, parent)
	proto_id = proto_id + 1;
	local func = {
		id = proto_id,
		source = r:string(),
		line_start = r:int(),
		line_end = r:int(),
		nups = r:byte(),
		nparams = r:byte(),
		is_vararg = r:byte(),
		maxstack = r:byte()
	}
	local ncode = r:int()
	func.code = {}
	for i = 1, ncode do
		local instr = r:int()
		local op = instr % 64;
		local a = math.floor(instr / 64) % 256;
		local c = math.floor(instr / 16384) % 512;
		local b = math.floor(instr / 8388608) % 512;
		local bx = math.floor(instr / 16384) % 262144;
		local sbx = bx - 131071;
		table.insert(func.code, {
			op = op,
			a = a,
			b = b,
			c = c,
			bx = bx,
			sbx = sbx
		})
	end;
	local nconst = r:int()
	func.constants = {}
	for i = 1, nconst do
		local t = r:byte()
		if t == 0 then
			table.insert(func.constants, {
				type = "nil"
			})
		elseif t == 1 then
			table.insert(func.constants, {
				type = "boolean",
				value = r:byte() ~= 0
			})
		elseif t == 3 then
			table.insert(func.constants, {
				type = "number",
				value = r:number()
			})
		elseif t == 4 then
			table.insert(func.constants, {
				type = "string",
				value = r:string()
			})
		end
	end;
	local nproto = r:int()
	func.protos = {}
	for i = 1, nproto do
		table.insert(func.protos, parse_function(r, func))
	end;
	local nlineinfo = r:int()
	for i = 1, nlineinfo do
		r:int()
	end;
	local nlocvars = r:int()
	for i = 1, nlocvars do
		r:string()
		r:int()
		r:int()
	end;
	local nupvalues = r:int()
	for i = 1, nupvalues do
		r:string()
	end;
	return func
end;
local function reg(n, func_id, version)
	if version and version > 0 then
		return "r" .. n .. "_" .. (func_id or 0) .. "_" .. version
	else
		return "r" .. n .. "_" .. (func_id or 0)
	end
end;
local function const_str(c)
	if c.type == "nil" then
		return "nil"
	elseif c.type == "boolean" then
		return c.value and "true" or "false"
	elseif c.type == "number" then
		return tostring(c.value)
	elseif c.type == "string" then
		return string.format("%q", c.value)
	end;
	return "?"
end;
local function is_ident(s)
	return s:match("^[%a_][%w_]*$") ~= nil
end;
local function emit(ctx, line)
	local indent_str = string.rep("  ", ctx.indent)
	table.insert(ctx.statements, indent_str .. line)
end;
local function get_reg_name(ctx, n)
	if not ctx.reg_names[n] then
		ctx.reg_names[n] = reg(n, ctx.func.id, ctx.reg_versions[n])
	end;
	return ctx.reg_names[n]
end;
local function new_reg_name(ctx, n)
	ctx.reg_versions[n] = (ctx.reg_versions[n] or 0) + 1
	local name = reg(n, ctx.func.id, ctx.reg_versions[n])
	ctx.reg_names[n] = name
	return name
end;
local function get_expr(ctx, n)
	return ctx.regs[n] or get_reg_name(ctx, n)
end;
local function set_expr(ctx, n, expr)
	ctx.regs[n] = expr
end;
local function get_rk(ctx, rk)
	if rk < 256 then
		return get_expr(ctx, rk)
	else
		return const_str(ctx.func.constants[rk - 256 + 1])
	end
end;
local function resolve_upval(ctx, idx)
	return ctx.upvalues[idx + 1] or ("upval_" .. idx)
end;
local function analyze_control_flow(func)
	local code = func.code;
	local block_ends = {}
	for pc = 1, #code do
		local ins = code[pc]
		if ins.op == OP.EQ or ins.op == OP.LT or ins.op == OP.LE or ins.op == OP.TEST or ins.op == OP.TESTSET then
			local next_ins = code[pc + 1]
			if next_ins and next_ins.op == OP.JMP then
				local jmp_target = pc + 2 + next_ins.sbx;
				if not block_ends[jmp_target] then
					block_ends[jmp_target] = {}
				end;
				table.insert(block_ends[jmp_target], "if")
			else
				if not block_ends[pc + 2] then
					block_ends[pc + 2] = {}
				end;
				table.insert(block_ends[pc + 2], "if")
			end
		end;
		if ins.op == OP.FORPREP then
			local loop_end = pc + 1 + ins.sbx + 1;
			if not block_ends[loop_end] then
				block_ends[loop_end] = {}
			end;
			table.insert(block_ends[loop_end], "for")
		end
	end;
	return {
		block_ends = block_ends
	}
end;
local function create_ctx(func, parent)
	return {
		func = func,
		parent = parent,
		regs = {},
		reg_names = {},
		reg_versions = {},
		declared = {},
		self_info = nil,
		tables = {},
		pending_closures = {},
		upvalues = {},
		indent = 0,
		statements = {},
		control_flow = analyze_control_flow(func)
	}
end;
local function build_table(ctx, reg, indent)
	local t = ctx.tables[reg]
	if not t then
		return "{}"
	end;
	local parts = {}
	for _, entry in ipairs(t.entries) do
		if entry.key_safe then
			table.insert(parts, entry.key .. " = " .. entry.val)
		else
			table.insert(parts, "[" .. entry.key .. "] = " .. entry.val)
		end
	end;
	for _, val in ipairs(t.array) do
		table.insert(parts, val)
	end;
	if #parts == 0 then
		return "{}"
	end;
	if #parts <= 3 and not t.has_func then
		return "{" .. table.concat(parts, ", ") .. "}"
	end;
	local lines = {}
	table.insert(lines, "{")
	for _, p in ipairs(parts) do
		table.insert(lines, string.rep("  ", indent + 1) .. p .. ",")
	end;
	table.insert(lines, string.rep("  ", indent) .. "}")
	return table.concat(lines, "\n")
end;
local function can_inline(ctx, reg)
	return false
end;
local decompile_func;
local function decompile_inline(ctx, proto, indent)
	local child = create_ctx(proto, ctx)
	child.indent = 0;
	decompile_func(child, proto)
	local lines = {}
	for _, s in ipairs(child.statements) do
		table.insert(lines, s)
	end;
	return "function(...)\n" .. table.concat(lines, "\n") .. "\nend"
end;
function decompile_func(ctx, func)
	local code = func.code;
	local n = #code;
	local pc = 1;
	local cf = ctx.control_flow;
	while pc <= n do
		if cf.block_ends[pc] then
			for _, block_type in ipairs(cf.block_ends[pc]) do
				ctx.indent = math.max(0, ctx.indent - 1)
				emit(ctx, "end")
			end
		end;
		local ins = code[pc]
		local op, a, b, c = ins.op, ins.a, ins.b, ins.c;
		local bx, sbx = ins.bx, ins.sbx;
		if op == OP.MOVE then
			set_expr(ctx, a, get_expr(ctx, b))
		elseif op == OP.LOADK then
			set_expr(ctx, a, const_str(func.constants[bx + 1]))
		elseif op == OP.LOADBOOL then
			set_expr(ctx, a, b ~= 0 and "true" or "false")
			if c ~= 0 then
				pc = pc + 1
			end
		elseif op == OP.LOADNIL then
			for i = a, b do
				set_expr(ctx, i, "nil")
			end
		elseif op == OP.GETUPVAL then
			set_expr(ctx, a, resolve_upval(ctx, b))
		elseif op == OP.GETGLOBAL then
			set_expr(ctx, a, func.constants[bx + 1].value)
		elseif op == OP.GETTABLE then
			local obj = get_expr(ctx, b)
			local key = get_rk(ctx, c)
			if c >= 256 then
				local kc = func.constants[c - 256 + 1]
				if kc.type == "string" and is_ident(kc.value) then
					set_expr(ctx, a, obj .. "." .. kc.value)
				else
					set_expr(ctx, a, obj .. "[" .. key .. "]")
				end
			else
				set_expr(ctx, a, obj .. "[" .. key .. "]")
			end
		elseif op == OP.SETGLOBAL then
			emit(ctx, func.constants[bx + 1].value .. " = " .. get_expr(ctx, a))
		elseif op == OP.SETUPVAL then
			emit(ctx, resolve_upval(ctx, b) .. " = " .. get_expr(ctx, a))
		elseif op == OP.SETTABLE then
			local key = get_rk(ctx, b)
			local val = c < 256 and ctx.pending_closures[c] or nil;
			if not val then
				val = get_rk(ctx, c)
			end;
			if c < 256 then
				ctx.pending_closures[c] = nil
			end;
			if ctx.tables[a] then
				local ks = false;
				local kn = key;
				if b >= 256 then
					local kc = func.constants[b - 256 + 1]
					if kc.type == "string" and is_ident(kc.value) then
						ks = true;
						kn = kc.value
					end
				end;
				if val:match("^function%(") then
					ctx.tables[a].has_func = true
				end;
				table.insert(ctx.tables[a].entries, {
					key = kn,
					val = val,
					key_safe = ks
				})
			else
				local obj = get_expr(ctx, a)
				local target;
				if b >= 256 then
					local kc = func.constants[b - 256 + 1]
					if kc.type == "string" and is_ident(kc.value) then
						target = obj .. "." .. kc.value
					else
						target = obj .. "[" .. key .. "]"
					end
				else
					target = obj .. "[" .. key .. "]"
				end;
				emit(ctx, target .. " = " .. val)
			end
		elseif op == OP.NEWTABLE then
			ctx.tables[a] = {
				entries = {},
				array = {},
				has_func = false
			}
			set_expr(ctx, a, nil)
		elseif op == OP.SELF then
			local obj = get_expr(ctx, b)
			local mn = nil;
			if c >= 256 then
				local kc = func.constants[c - 256 + 1]
				if kc.type == "string" then
					mn = kc.value
				end
			end;
			ctx.self_info = {
				obj = obj,
				method = mn,
				method_raw = get_rk(ctx, c)
			}
			set_expr(ctx, a + 1, obj)
			if mn and is_ident(mn) then
				set_expr(ctx, a, obj .. ":" .. mn)
			else
				set_expr(ctx, a, obj .. "[" .. ctx.self_info.method_raw .. "]")
			end
		elseif op >= OP.ADD and op <= OP.POW then
			local ops = {
				[OP.ADD] = "+",
				[OP.SUB] = "-",
				[OP.MUL] = "*",
				[OP.DIV] = "/",
				[OP.MOD] = "%",
				[OP.POW] = "^"
			}
			set_expr(ctx, a, get_rk(ctx, b) .. " " .. ops[op] .. " " .. get_rk(ctx, c))
		elseif op == OP.UNM then
			set_expr(ctx, a, "-" .. get_expr(ctx, b))
		elseif op == OP.NOT then
			set_expr(ctx, a, "not " .. get_expr(ctx, b))
		elseif op == OP.LEN then
			set_expr(ctx, a, "#" .. get_expr(ctx, b))
		elseif op == OP.CONCAT then
			local p = {}
			for i = b, c do
				table.insert(p, get_expr(ctx, i))
			end;
			set_expr(ctx, a, table.concat(p, " .. "))
		elseif op == OP.JMP then
		elseif op == OP.EQ or op == OP.LT or op == OP.LE then
			local cmp;
			if op == OP.EQ then
				cmp = (a ~= 0) and "~=" or "=="
			elseif op == OP.LT then
				cmp = (a ~= 0) and ">=" or "<"
			else
				cmp = (a ~= 0) and ">" or "<="
			end;
			emit(ctx, "if " .. get_rk(ctx, b) .. " " .. cmp .. " " .. get_rk(ctx, c) .. " then")
			ctx.indent = ctx.indent + 1
		elseif op == OP.TEST then
			local cond = (c == 0) and "not " .. get_expr(ctx, a) or get_expr(ctx, a)
			emit(ctx, "if " .. cond .. " then")
			ctx.indent = ctx.indent + 1
		elseif op == OP.TESTSET then
			local cond = (c == 0) and "not " .. get_expr(ctx, b) or get_expr(ctx, b)
			set_expr(ctx, a, get_expr(ctx, b))
			emit(ctx, "if " .. cond .. " then")
			ctx.indent = ctx.indent + 1
		elseif op == OP.CALL then
			local fe;
			local args = {}
			if ctx.self_info then
				local si = ctx.self_info;
				if si.method and is_ident(si.method) then
					fe = si.obj .. ":" .. si.method
				else
					fe = si.obj .. "[" .. si.method_raw .. "]"
				end;
				if b > 2 then
					for i = a + 2, a + b - 1 do
						local ae = get_expr(ctx, i)
						if ctx.tables[i] then
							ae = build_table(ctx, i, ctx.indent)
							ctx.tables[i] = nil
						end;
						if ctx.pending_closures[i] then
							ae = ctx.pending_closures[i]
							ctx.pending_closures[i] = nil
						end;
						table.insert(args, ae)
					end
				elseif b == 0 then
					local ae = get_expr(ctx, a + 1)
					if ae and ae ~= reg(a + 1, ctx.func.id) then
						table.insert(args, ae)
					end
				end;
				ctx.self_info = nil
			else
				fe = get_expr(ctx, a)
				if b > 1 then
					for i = a + 1, a + b - 1 do
						local ae = get_expr(ctx, i)
						if ctx.tables[i] then
							ae = build_table(ctx, i, ctx.indent)
							ctx.tables[i] = nil
						end;
						if ctx.pending_closures[i] then
							ae = ctx.pending_closures[i]
							ctx.pending_closures[i] = nil
						end;
						table.insert(args, ae)
					end
				elseif b == 0 then
					local ae = get_expr(ctx, a + 1)
					if ae and ae ~= reg(a + 1, ctx.func.id) then
						table.insert(args, ae)
					end
				end
			end;
			local call = fe .. "(" .. table.concat(args, ", ") .. ")"
			if c == 0 then
				set_expr(ctx, a, call)
			elseif c == 1 then
				emit(ctx, call)
			elseif c == 2 then
				local rn = new_reg_name(ctx, a)
				emit(ctx, "local " .. rn .. " = " .. call)
				set_expr(ctx, a, rn)
			else
				local rets = {}
				for i = a, a + c - 2 do
					local rn = new_reg_name(ctx, i)
					table.insert(rets, rn)
					set_expr(ctx, i, rn)
				end;
				emit(ctx, "local " .. table.concat(rets, ", ") .. " = " .. call)
			end
		elseif op == OP.TAILCALL then
			local fe = get_expr(ctx, a)
			local args = {}
			if b > 1 then
				for i = a + 1, a + b - 1 do
					table.insert(args, get_expr(ctx, i))
				end
			end;
			emit(ctx, "return " .. fe .. "(" .. table.concat(args, ", ") .. ")")
		elseif op == OP.RETURN then
			if b == 1 then
				emit(ctx, "return")
			elseif b == 2 then
				emit(ctx, "return " .. get_expr(ctx, a))
			else
				local rets = {}
				for i = a, a + b - 2 do
					table.insert(rets, get_expr(ctx, i))
				end;
				emit(ctx, "return " .. table.concat(rets, ", "))
			end
		elseif op == OP.FORLOOP then
		elseif op == OP.FORPREP then
			emit(ctx, "for " .. new_reg_name(ctx, a + 3) .. " = " .. get_expr(ctx, a) .. ", " .. get_expr(ctx, a + 1) .. ", " .. get_expr(ctx, a + 2) .. " do")
			ctx.indent = ctx.indent + 1;
		elseif op == OP.TFORLOOP then
			local vars = {}
			for i = a + 3, a + 2 + c do
				table.insert(vars, new_reg_name(ctx, i))
			end;
			emit(ctx, "for " .. table.concat(vars, ", ") .. " in " .. get_expr(ctx, a) .. " do")
			ctx.indent = ctx.indent + 1
		elseif op == OP.SETLIST then
			if ctx.tables[a] then
				for i = 1, b do
					table.insert(ctx.tables[a].array, get_expr(ctx, a + i))
				end
			end
		elseif op == OP.CLOSURE then
			local proto = func.protos[bx + 1]
			local params = {}
			for i = 0, proto.nparams - 1 do
				table.insert(params, reg(i, proto.id))
			end;
			if proto.is_vararg ~= 0 then
				table.insert(params, "...")
			end;
			if can_inline(ctx, a) then
				local ic = decompile_inline(ctx, proto, ctx.indent)
				ctx.pending_closures[a] = ic;
				set_expr(ctx, a, ic)
			else
				local next_ins = code[pc + 1]
				local is_named = next_ins and next_ins.op == OP.SETGLOBAL and next_ins.a == a;
				local fn = is_named and func.constants[next_ins.bx + 1].value or nil;
				if fn and not is_ident(fn) then
					fn = nil;
					is_named = false
				end;
				if is_named then
					emit(ctx, "function " .. fn .. "(" .. table.concat(params, ", ") .. ")")
				else
					emit(ctx, "local " .. new_reg_name(ctx, a) .. " = function(" .. table.concat(params, ", ") .. ")")
				end;
				emit(ctx, "  -- line: [" .. proto.line_start .. ", " .. proto.line_end .. "] id: " .. proto.id)
				local child = create_ctx(proto, ctx)
				for i = 1, proto.nups do
					local up_ins = code[pc + i]
					if up_ins.op == OP.MOVE then
						child.upvalues[i] = get_expr(ctx, up_ins.b)
					elseif up_ins.op == OP.GETUPVAL then
						child.upvalues[i] = resolve_upval(ctx, up_ins.b)
					end
				end;
				child.indent = ctx.indent + 1;
				decompile_func(child, proto)
				for _, s in ipairs(child.statements) do
					table.insert(ctx.statements, s)
				end;
				emit(ctx, "end")
				if is_named then
					pc = pc + 1
				end
			end;
			pc = pc + proto.nups
		elseif op == OP.CLOSE then
		elseif op == OP.VARARG then
			if b == 0 then
				set_expr(ctx, a, "...")
			else
				local vars = {}
				for i = a, a + b - 2 do
					table.insert(vars, new_reg_name(ctx, i))
				end;
				emit(ctx, "local " .. table.concat(vars, ", ") .. " = ...")
			end
		else
			emit(ctx, "-- UNKNOWN OP: " .. (OP_NAME[op] or op))
		end;
		pc = pc + 1
	end
end;
local f = io.open(infile, "rb")
if not f then
	io.stderr:write("Error: Cannot open " .. infile .. "\n")
	os.exit(1)
end;
local data = f:read("*a")
f:close()
print("Decompiling: " .. infile)
local reader = Reader:new(data)
parse_header(reader)
local main = parse_function(reader, nil)
local ctx = create_ctx(main, nil)
local success, err = pcall(decompile_func, ctx, main)
if not success then
	io.stderr:write("Decompilation error: " .. tostring(err) .. "\n")
	os.exit(1)
end;
local out = io.open(outfile, "w")
if out then
	for _, line in ipairs(ctx.statements) do
		out:write(line .. "\n")
	end;
	out:flush()
	out:close()
	print("Output saved to: " .. outfile)
else
	io.stderr:write("Error: Cannot write to " .. outfile .. "\n")
	os.exit(1)
end
