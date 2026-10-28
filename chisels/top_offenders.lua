-- Per-comm subtree event volume of a capture, as JSON.
--
-- An event is credited to its own process comm and to every distinct comm in its ancestry
-- (up to `depth` levels), because skip_events_by_process suppresses a matching process and
-- all of its descendants. Each distinct ancestry chain is also counted per second, so a
-- consumer can compute the exact effect of any skip list without another pass.
-- Output schema: see README.md ("JSON contract").

description = "Per-comm event volume including descendants (JSON), for choosing skip_events_by_process entries."
short_description = "Top offenders by subtree event count (JSON)"
category = "Performance"

args = {
	{
		name = "depth",
		description = "Ancestor levels to walk (e.g. 12)",
		argtype = "int",
	},
	{
		name = "max_chains",
		description = "Maximum distinct ancestry chains in the output (e.g. 5000)",
		argtype = "int",
	},
}

local depth = 12
local max_chains = 5000

function on_set_arg(name, val)
	if name == "depth" then
		depth = tonumber(val)
		return depth ~= nil and depth >= 0
	elseif name == "max_chains" then
		max_chains = tonumber(val)
		return max_chains ~= nil and max_chains > 0
	end
	return false
end

local ftime, fexe, fcmd
local fanames = {}
local min_sec, max_sec
local total_events = 0
local total_sec = {}
-- Comms are keyed by a small integer id so chain keys never depend on the bytes of a name.
local ids = {}
local names = {}
local comms = {}
local chains = {}

function on_init()
	ftime = chisel.request_field("evt.rawtime")
	fexe = chisel.request_field("proc.exe")
	fcmd = chisel.request_field("proc.cmdline")
	for j = 0, depth do
		fanames[j] = chisel.request_field("proc.aname[" .. j .. "]")
	end
	return true
end

local seen = {}

function on_event()
	local rawtime = evt.field(ftime)
	if rawtime == nil then
		return true
	end
	local sec = math.floor(rawtime / 1000000000)
	if min_sec == nil or sec < min_sec then
		min_sec = sec
	end
	if max_sec == nil or sec > max_sec then
		max_sec = sec
	end

	total_events = total_events + 1
	total_sec[sec] = (total_sec[sec] or 0) + 1

	local nseen = 0
	for j = 0, depth do
		local name = evt.field(fanames[j])
		if name == nil then
			break
		end
		local id = ids[name]
		if id == nil then
			id = #names + 1
			ids[name] = id
			names[id] = name
			comms[id] = { subtree = 0, self = 0, sec = {} }
		end
		local dup = false
		for k = 1, nseen do
			if seen[k] == id then
				dup = true
				break
			end
		end
		if not dup then
			nseen = nseen + 1
			seen[nseen] = id
			local c = comms[id]
			c.subtree = c.subtree + 1
			c.sec[sec] = (c.sec[sec] or 0) + 1
			if j == 0 then
				c.self = c.self + 1
				if c.exe == nil then
					c.exe = evt.field(fexe) or ""
					c.cmd = evt.field(fcmd) or ""
				end
			end
		end
	end

	-- An empty chain is an event with no known process (e.g. async plugin events); no skip
	-- list can remove it, and keeping it makes the chain counts sum to `events`.
	local sig = table.concat(seen, ",", 1, nseen)
	local ch = chains[sig]
	if ch == nil then
		ch = { n = 0, sec = {} }
		chains[sig] = ch
	end
	ch.n = ch.n + 1
	ch.sec[sec] = (ch.sec[sec] or 0) + 1
	return true
end

-- Length of the valid UTF-8 sequence starting at byte i of s, or nil.
local function utf8_len(s, i)
	local b = s:byte(i)
	local function cont(k)
		local c = s:byte(i + k)
		return c ~= nil and c >= 0x80 and c <= 0xBF
	end
	if b >= 0xC2 and b <= 0xDF then
		return cont(1) and 2 or nil
	elseif b >= 0xE0 and b <= 0xEF then
		if not (cont(1) and cont(2)) then
			return nil
		end
		local c1 = s:byte(i + 1)
		if (b == 0xE0 and c1 < 0xA0) or (b == 0xED and c1 > 0x9F) then
			return nil
		end
		return 3
	elseif b >= 0xF0 and b <= 0xF4 then
		if not (cont(1) and cont(2) and cont(3)) then
			return nil
		end
		local c1 = s:byte(i + 1)
		if (b == 0xF0 and c1 < 0x90) or (b == 0xF4 and c1 > 0x8F) then
			return nil
		end
		return 4
	end
	return nil
end

-- Valid UTF-8 is kept as is; bytes that are not valid UTF-8 become U+FFFD.
local function esc(s)
	s = tostring(s)
	local out = {}
	local i = 1
	while i <= #s do
		local b = s:byte(i)
		if b == 0x22 then
			out[#out + 1] = '\\"'
			i = i + 1
		elseif b == 0x5C then
			out[#out + 1] = "\\\\"
			i = i + 1
		elseif b < 0x20 or b == 0x7F then
			out[#out + 1] = string.format("\\u%04x", b)
			i = i + 1
		elseif b < 0x80 then
			out[#out + 1] = string.char(b)
			i = i + 1
		else
			local n = utf8_len(s, i)
			if n then
				out[#out + 1] = s:sub(i, i + n - 1)
				i = i + n
			else
				out[#out + 1] = "\\ufffd"
				i = i + 1
			end
		end
	end
	return '"' .. table.concat(out) .. '"'
end

local function dense(tbl)
	local out = {}
	for s = min_sec, max_sec do
		out[#out + 1] = tostring(tbl[s] or 0)
	end
	return "[" .. table.concat(out, ",") .. "]"
end

function on_capture_end()
	if min_sec == nil then
		print('{"version":2,"events":0,"comms":[],"chains":[]}')
		return true
	end

	local order = {}
	for id = 1, #names do
		order[id] = id
	end
	table.sort(order, function(a, b)
		if comms[a].subtree ~= comms[b].subtree then
			return comms[a].subtree > comms[b].subtree
		end
		return names[a] < names[b]
	end)
	local index = {}
	local cparts = {}
	for pos, id in ipairs(order) do
		index[id] = pos - 1
		local c = comms[id]
		cparts[pos] = string.format(
			'{"comm":%s,"subtree":%d,"self":%d,"exe":%s,"cmdline":%s,"sec":%s}',
			esc(names[id]), c.subtree, c.self, esc(c.exe or ""), esc(c.cmd or ""), dense(c.sec))
	end

	local sigs = {}
	for sig in pairs(chains) do
		sigs[#sigs + 1] = sig
	end
	table.sort(sigs, function(a, b)
		if chains[a].n ~= chains[b].n then
			return chains[a].n > chains[b].n
		end
		return a < b
	end)
	local kept = math.min(#sigs, max_chains)
	local dropped_events = 0
	for i = kept + 1, #sigs do
		dropped_events = dropped_events + chains[sigs[i]].n
	end
	local chparts = {}
	for i = 1, kept do
		local ch = chains[sigs[i]]
		local idx = {}
		for id in sigs[i]:gmatch("%d+") do
			idx[#idx + 1] = tostring(index[tonumber(id)])
		end
		chparts[i] = string.format('{"c":[%s],"n":%d,"sec":%s}',
			table.concat(idx, ","), ch.n, dense(ch.sec))
	end

	print(string.format(
		'{"version":2,"depth":%d,"start_sec":%d,"end_sec":%d,"events":%d,"total_sec":%s,'
			.. '"chains_total":%d,"chains_listed":%d,"chains_dropped_events":%d,'
			.. '"comms":[%s],"chains":[%s]}',
		depth, min_sec, max_sec, total_events, dense(total_sec),
		#sigs, kept, dropped_events, table.concat(cparts, ","), table.concat(chparts, ",")))
	return true
end
