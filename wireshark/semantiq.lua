-- tid-semantiQ findings inside Wireshark.
--
-- A post-dissector that attaches semantiQ's findings to the packets they
-- are about, as an ordinary protocol subtree. Once loaded you can:
--
--   * filter:        semantiq                      (any annotated packet)
--                    semantiq.severity == "HIGH"
--                    semantiq.rule contains "beacon"
--   * add a column:  right-click a semantiq field -> Apply as Column
--   * read verdicts: select a packet, open the "tid-semantiQ" subtree
--
-- THE PLUGIN HOLDS NO OPINION. All analysis happens in semantiQ, which
-- writes an annotations file (semantiq.py read capture.pcap
-- --wireshark-lua capture.lua); this plugin only looks packets up in it,
-- by frame number and by TCP stream index. It can therefore never
-- disagree with the report — by construction, not by discipline.
--
-- INSTALL. Copy this file into your personal Lua plugins directory
-- (Wireshark: Help -> About -> Folders -> "Personal Lua Plugins",
-- typically ~/.local/lib/wireshark/plugins/). Then point it at an
-- annotations file, either way:
--   * Edit -> Preferences -> Protocols -> SEMANTIQ -> annotations file
--   * export SEMANTIQ_ANNOTATIONS=/path/to/capture.lua before launching
--
-- SAFETY. The annotations file is executed by Lua's dofile, so this
-- plugin refuses files that are not the pure-data shape the exporter
-- writes: the file must start with "return {" after its comment lines.
-- Keep annotations files alongside their captures and treat them with
-- the same care — both describe, and came from, the same traffic.

local proto = Proto("semantiq", "tid-semantiQ findings")

local f_rule       = ProtoField.string("semantiq.rule", "Rule")
local f_title      = ProtoField.string("semantiq.title", "Finding")
local f_severity   = ProtoField.string("semantiq.severity", "Severity")
local f_confidence = ProtoField.string("semantiq.confidence", "Confidence")
local f_source     = ProtoField.string("semantiq.source", "Analysed capture")
local f_bpf        = ProtoField.string("semantiq.bpf", "Capture filter (re-capture this flow)")
proto.fields = { f_rule, f_title, f_severity, f_confidence, f_source, f_bpf }

proto.prefs.datafile = Pref.string(
    "annotations file",
    "",
    "Path to the annotations file written by: "
        .. "semantiq.py read <capture> --wireshark-lua <file>")

-- Read, not registered: a post-dissector may read fields other
-- dissectors filled in. Declared at file scope as the API requires.
local tcp_stream_field = Field.new("tcp.stream")

local annotations = nil     -- the loaded table, or nil
local loaded_from = nil     -- the path it came from, for the summary
local warned = false

local function looks_like_pure_data(path)
    local handle = io.open(path, "r")
    if handle == nil then return false end
    for line in handle:lines() do
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed ~= "" and trimmed:sub(1, 2) ~= "--" then
            handle:close()
            -- The first significant line of an exporter file is exactly
            -- "return {": anything else is not an annotations file and
            -- will not be executed.
            return trimmed == "return {"
        end
    end
    handle:close()
    return false
end

local function try_load(path)
    if path == nil or path == "" then return nil end
    if not looks_like_pure_data(path) then
        print("semantiq: refusing " .. path
              .. " (not a pure-data annotations file)")
        return nil
    end
    local ok, data = pcall(dofile, path)
    if ok and type(data) == "table" then
        loaded_from = path
        return data
    end
    print("semantiq: could not load " .. path)
    return nil
end

local function candidate_paths()
    local paths = {}
    if proto.prefs.datafile ~= "" then
        paths[#paths + 1] = proto.prefs.datafile
    end
    local env = os.getenv("SEMANTIQ_ANNOTATIONS")
    if env ~= nil and env ~= "" then
        paths[#paths + 1] = env
    end
    return paths
end

function proto.init()
    annotations = nil
    loaded_from = nil
    warned = false
    for _, path in ipairs(candidate_paths()) do
        annotations = try_load(path)
        if annotations ~= nil then break end
    end
end

local function findings_for(pinfo)
    if annotations == nil then return nil end
    local found = nil
    local frame_hits = annotations.by_frame
        and annotations.by_frame[pinfo.number]
    if frame_hits ~= nil then
        found = {}
        for _, hit in ipairs(frame_hits) do found[#found + 1] = hit end
    end
    local stream = tcp_stream_field()
    if stream ~= nil and annotations.by_tcp_stream ~= nil then
        local stream_hits = annotations.by_tcp_stream[stream.value]
        if stream_hits ~= nil then
            found = found or {}
            for _, hit in ipairs(stream_hits) do found[#found + 1] = hit end
        end
    end
    return found
end

function proto.dissector(buffer, pinfo, tree)
    if annotations == nil then
        if not warned then
            warned = true
            print("semantiq: no annotations loaded — set the preference, "
                  .. "SEMANTIQ_ANNOTATIONS, or generate one with "
                  .. "--wireshark-lua")
        end
        return
    end
    local found = findings_for(pinfo)
    if found == nil or #found == 0 then return end

    local subtree = tree:add(proto, "tid-semantiQ: "
        .. #found .. " finding(s)")
    if annotations.source ~= nil and annotations.source ~= "" then
        subtree:add(f_source, annotations.source):set_generated()
    end
    for _, hit in ipairs(found) do
        local item = subtree:add(f_title, hit.title or "?")
        item:set_generated()
        subtree:add(f_rule, hit.rule or "?"):set_generated()
        subtree:add(f_severity, hit.severity or "?"):set_generated()
        subtree:add(f_confidence,
                    string.format("%.2f", hit.confidence or 0)):set_generated()
        if hit.bpf ~= nil and hit.bpf ~= "" then
            -- The capture filter to re-capture this flow live. Shown as a
            -- field so it can be selected and copied, and applied as a
            -- column; Wireshark's Lua has no clipboard call to make it one
            -- keystroke, so "there where you need it" is the honest promise.
            subtree:add(f_bpf, hit.bpf):set_generated()
        end
    end
end

register_postdissector(proto)

-- A summary window and a reload action, when a GUI is present.
if gui_enabled() then
    local function show_summary()
        local window = TextWindow.new("tid-semantiQ findings")
        if annotations == nil then
            window:set("No annotations loaded.\n\n"
                .. "Generate one:\n"
                .. "  semantiq.py read capture.pcap "
                .. "--wireshark-lua capture.lua\n\n"
                .. "Then set Edit -> Preferences -> Protocols -> SEMANTIQ,\n"
                .. "or export SEMANTIQ_ANNOTATIONS, and reload Lua "
                .. "(Analyze -> Reload Lua Plugins).")
            return
        end
        local lines = { "Annotations: " .. (loaded_from or "?"),
                        "Capture:     " .. (annotations.source or "?"), "" }
        local function dump(label, bucket, filter_fmt)
            if bucket == nil then return end
            local keys = {}
            for key in pairs(bucket) do keys[#keys + 1] = key end
            table.sort(keys)
            for _, key in ipairs(keys) do
                for _, hit in ipairs(bucket[key]) do
                    lines[#lines + 1] = string.format(
                        "[%-8s] %.2f  %s\n           %s  ->  " .. filter_fmt,
                        hit.severity or "?", hit.confidence or 0,
                        hit.title or "?", hit.rule or "?", key)
                    if hit.bpf ~= nil and hit.bpf ~= "" then
                        lines[#lines + 1] = "           capture:  " .. hit.bpf
                    end
                end
            end
        end
        dump("stream", annotations.by_tcp_stream, "tcp.stream eq %d")
        dump("frame", annotations.by_frame, "frame.number == %d")
        window:set(table.concat(lines, "\n"))
    end
    register_menu("tid-semantiQ/Findings summary",
                  show_summary, MENU_TOOLS_UNSORTED)
    register_menu("tid-semantiQ/Reload annotations",
                  function () proto.init(); reload_packets() end,
                  MENU_TOOLS_UNSORTED)
end
