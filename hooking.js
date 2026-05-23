// HOOKING - MCSettingsEvents / MCProfileEvents Scanner

const APP_NAME = "HOOKING"
const CREDIT = "SANTOS e r3"
const DISCORD = "discord.gg/hooking"

async function alertMsg(title, message) {
  let a = new Alert()
  a.title = title
  a.message = message
  a.addAction("OK")
  await a.present()
}

function isMCFile(path) {
  let lower = path.toLowerCase()
  return (
    lower.includes("mcsettingsevents") ||
    lower.includes("mcprofileevents")
  )
}

function getFileType(path) {
  let lower = path.toLowerCase()
  if (lower.includes("mcsettingsevents")) return "MCSettingsEvents"
  if (lower.includes("mcprofileevents")) return "MCProfileEvents"
  return "MC"
}

function walkDirectory(fm, dir, files = []) {
  for (let item of fm.listContents(dir)) {
    let path = fm.joinPath(dir, item)

    if (fm.isDirectory(path)) {
      walkDirectory(fm, path, files)
    } else if (isMCFile(path)) {
      files.push(path)
    }
  }

  return files
}

function readTextSafe(fm, path) {
  try {
    return fm.readString(path)
  } catch (e) {
    return ""
  }
}

function normalizeRawText(content) {
  return String(content || "")
    .replace(/\u0000/g, "")
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, " ")
    .replace(/\s+/g, " ")
}

function cleanCode(code) {
  return String(code || "")
    .replace(/^[^a-zA-Z0-9]+/, "")
    .replace(/[^a-zA-Z0-9._~\-]+$/, "")
    .trim()
}

function isNoise(code) {
  let lower = code.toLowerCase()

  let blocked = [
    "apple.com",
    "doctype",
    "plist",
    "version",
    "encoding",
    "timestamp",
    "operation",
    "process",
    "dictionary",
    "string",
    "integer",
    "array",
    "true",
    "false",
    "systemsettings",
    "restrictions",
    "clientrestrictions",
    "systemclientrestrictions",
    "effective"
  ]

  return blocked.some(x => lower.includes(x))
}

function classifyCode(code) {
  let lower = code.toLowerCase()

  if (/^[a-f0-9]{64,128}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(code)) return "Hash + UUID"
  if (/^[a-f0-9]{64,128}$/i.test(code)) return "Hash/Certificado"
  if (/^(com|xyz|net|org)\.[a-zA-Z0-9._~\-]{4,240}$/i.test(code)) return "Perfil"
  if (lower.includes("khoindvn") || lower.includes("khoivdon")) return "Perfil DNS"
  return "Código"
}

function isWantedCode(code) {
  let lower = code.toLowerCase()

  if (!code || code.length < 12) return false
  if (isNoise(code)) return false

  if (/^[a-f0-9]{64,128}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(code)) return true
  if (/^[a-f0-9]{64,128}$/i.test(code)) return true
  if (/^(com|xyz|net|org)\.[a-zA-Z0-9._~\-]{4,240}$/i.test(code)) return true

  if (lower.includes("khoindvn")) return true
  if (lower.includes("khoivdon")) return true
  if (lower.includes("apple-dns")) return true
  if (lower.includes("fatality")) return true
  if (lower.includes("freefire")) return true
  if (lower.includes("aimbot")) return true
  if (lower.includes("vpn")) return true
  if (lower.includes("dns")) return true

  return false
}

function findOperations(text) {
  let ops = []
  let regex = /(install|installed|remove|removed|removal)/gi
  let m

  while ((m = regex.exec(text)) !== null) {
    let raw = m[1].toLowerCase()
    ops.push({
      type: raw.includes("install") ? "Instalação" : "Remoção",
      index: m.index
    })
  }

  return ops
}

function nearestOperation(ops, index, distanceLimit) {
  let best = null
  let bestDistance = Infinity

  for (let op of ops) {
    let d = Math.abs(op.index - index)

    if (d < bestDistance && d <= distanceLimit) {
      best = op
      bestDistance = d
    }
  }

  return best
}

function dateNear(text, index) {
  let block = text.slice(Math.max(0, index - 5000), Math.min(text.length, index + 5000))

  let patterns = [
    /\d{2}\/\d{2}\/\d{4}[, ]+\d{2}:\d{2}:\d{2}/,
    /\d{2}-\d{2}-\d{4}[, ]+\d{2}:\d{2}:\d{2}/,
    /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/,
    /\d{2}\/\d{2}\/\d{2}[, ]+\d{2}:\d{2}:\d{2}/,
    /\d{2}:\d{2}:\d{2}/
  ]

  for (let p of patterns) {
    let m = block.match(p)
    if (m) return m[0]
  }

  return "Horário não encontrado"
}

function removeSubMatches(codes) {
  let sorted = codes.slice().sort((a, b) => b.code.length - a.code.length)
  let final = []

  for (let item of sorted) {
    let existsInsideBigger = final.some(big => {
      return big.code !== item.code && big.code.includes(item.code)
    })

    if (!existsInsideBigger) final.push(item)
  }

  return final
}

function extractCodes(text) {
  let found = []

  let regexes = [
    /([a-f0-9]{64,128}-[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})/gi,
    /((?:com|xyz|net|org)\.[a-zA-Z0-9._~\-]{4,240})/g,
    /([a-f0-9]{64,128})/gi,
    /([a-zA-Z0-9._~\-]*khoindvn[a-zA-Z0-9._~\-]*)/gi,
    /([a-zA-Z0-9._~\-]*khoivdon[a-zA-Z0-9._~\-]*)/gi
  ]

  for (let regex of regexes) {
    let m

    while ((m = regex.exec(text)) !== null) {
      let code = cleanCode(m[1])
      if (!isWantedCode(code)) continue

      found.push({
        code,
        index: m.index,
        codeType: classifyCode(code)
      })
    }
  }

  return removeSubMatches(found)
}

function uniqueEvents(events) {
  let map = {}

  for (let ev of events) {
    let key = `${ev.source}|${ev.action}|${ev.code}`
    if (!map[key]) map[key] = ev
  }

  return Object.values(map)
}

function extractEvents(content, file) {
  let source = getFileType(file)
  let text = normalizeRawText(content)
  let ops = findOperations(text)
  let codes = extractCodes(text)
  let events = []

  for (let c of codes) {
    let limit = source === "MCSettingsEvents" ? 999999 : 7000
    let op = nearestOperation(ops, c.index, limit)

    if (source === "MCProfileEvents" && !op) continue

    let action = op ? op.type : "Detectado"
    let date = op ? dateNear(text, c.index) : "Sem install/remove próximo"

    events.push({
      source,
      action,
      code: c.code,
      codeType: c.codeType,
      date,
      file
    })
  }

  return uniqueEvents(events)
}

function generateHtml(data) {
  let installed = data.events.filter(e => e.action === "Instalação")
  let removed = data.events.filter(e => e.action === "Remoção")
  let detected = data.events.filter(e => e.action === "Detectado")
  let mcSettingsEvents = data.events.filter(e => e.source === "MCSettingsEvents")
  let mcProfileEvents = data.events.filter(e => e.source === "MCProfileEvents")

  function card(ev) {
    let cls = ev.action === "Remoção" ? "remove" : ev.action === "Instalação" ? "install" : "event"

    return `
      <div class="card">
        <div class="card-main">
          <span class="tag ${cls}">${ev.action}</span>
          <span class="source">${ev.source}</span>
          <span class="type">${ev.codeType}</span>
          <div class="code">${ev.code}</div>
          <div class="file">${ev.file.split("/").pop()}</div>
        </div>
        <div class="date">${ev.date}</div>
      </div>
    `
  }

  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>${APP_NAME}</title>
<style>
body {
  background:#050505;
  color:#eee;
  font-family: Menlo, monospace;
  padding:22px;
}
.header {
  text-align:center;
  margin-top:24px;
  margin-bottom:42px;
  padding:22px 0 14px 0;
}
.main-name {
  color:#ffffff;
  font-size:76px;
  font-weight:900;
  letter-spacing:14px;
  text-shadow:0 0 14px #fff, 0 0 32px #fff, 0 0 55px #777;
  line-height:1;
}
.credits {
  margin-top:20px;
  color:#bbbbbb;
  font-size:24px;
  letter-spacing:4px;
  line-height:1.9;
  text-shadow:0 0 8px #555;
}
.discord {
  color:#ffffff;
  font-size:26px;
  font-weight:700;
  text-shadow:0 0 10px #fff, 0 0 18px #777;
}
.section {
  border:1px solid #222;
  padding:18px;
  margin:22px 0;
  background:#080808;
}
.title {
  color:#888;
  letter-spacing:5px;
  margin-bottom:18px;
}
.row {
  display:flex;
  justify-content:space-between;
  border-bottom:1px solid #111;
  padding:12px 0;
}
.label { color:#888; }
.value { color:#fff; }
.card {
  border:1px solid #181818;
  padding:14px;
  margin:12px 0;
  background:#0b0b0b;
  display:flex;
  justify-content:space-between;
  gap:16px;
}
.card-main {
  flex:1;
  min-width:0;
}
.tag {
  padding:5px 10px;
  border-radius:4px;
  font-size:12px;
}
.install {
  background:#063b1e;
  color:#6bff9e;
}
.remove {
  background:#410610;
  color:#ff5c72;
}
.event {
  background:#302406;
  color:#ffd56b;
}
.source {
  color:#ffd56b;
  margin-left:8px;
  font-size:12px;
}
.type {
  color:#777;
  margin-left:8px;
  font-size:12px;
}
.code {
  margin-top:12px;
  color:#fff;
  font-size:16px;
  word-break:break-all;
}
.file {
  margin-top:8px;
  color:#555;
  font-size:12px;
}
.date {
  color:#aaa;
  white-space:nowrap;
  font-size:13px;
  text-align:right;
}
</style>
</head>
<body>

<div class="header">
  <div class="main-name">${APP_NAME}</div>
  <div class="credits">CRÉDITOS: ${CREDIT}<br><span class="discord">${DISCORD}</span></div>
</div>

<div class="section">
  <div class="title">◆ ARQUIVOS ANALISADOS</div>
  <div class="row"><span class="label">Arquivos lidos</span><span class="value">${data.filesRead}</span></div>
  <div class="row"><span class="label">Eventos únicos</span><span class="value">${data.events.length}</span></div>
  <div class="row"><span class="label">MCSettingsEvents</span><span class="value">${mcSettingsEvents.length}</span></div>
  <div class="row"><span class="label">MCProfileEvents</span><span class="value">${mcProfileEvents.length}</span></div>
</div>

<div class="section">
  <div class="title">◆ PERFIS INSTALADOS (${installed.length})</div>
  ${installed.length ? installed.map(card).join("") : "<p>Nenhuma instalação encontrada.</p>"}
</div>

<div class="section">
  <div class="title">◆ PERFIS REMOVIDOS (${removed.length})</div>
  ${removed.length ? removed.map(card).join("") : "<p>Nenhuma remoção encontrada.</p>"}
</div>

<div class="section">
  <div class="title">◆ MCSETTINGSEVENTS (${mcSettingsEvents.length})</div>
  ${mcSettingsEvents.length ? mcSettingsEvents.map(card).join("") : "<p>Nenhum hash/perfil encontrado na MCSettingsEvents.</p>"}
</div>

<div class="section">
  <div class="title">◆ MCPROFILEEVENTS (${mcProfileEvents.length})</div>
  ${mcProfileEvents.length ? mcProfileEvents.map(card).join("") : "<p>Nenhum evento encontrado na MCProfileEvents.</p>"}
</div>

<div class="section">
  <div class="title">◆ DETECTADOS SEM AÇÃO (${detected.length})</div>
  ${detected.length ? detected.map(card).join("") : "<p>Nenhum detectado sem ação.</p>"}
</div>

</body>
</html>
`
}

async function getInputPath() {
  await alertMsg("Hooking", "Selecione a pasta extraída da sysdiagnose e toque em Abrir.")
  return await DocumentPicker.openFolder()
}

async function main() {
  let fm = FileManager.local()
  let input = await getInputPath()
  let files = fm.isDirectory(input) ? walkDirectory(fm, input) : [input]

  let allEvents = []
  let filesRead = 0

  for (let file of files) {
    if (!isMCFile(file)) continue

    let content = readTextSafe(fm, file)
    if (!content) continue

    filesRead++
    allEvents.push(...extractEvents(content, file))
  }

  let cleanEvents = uniqueEvents(allEvents)

  cleanEvents.sort((a, b) => {
    if (a.source === "MCSettingsEvents" && b.source !== "MCSettingsEvents") return -1
    if (a.source !== "MCSettingsEvents" && b.source === "MCSettingsEvents") return 1
    if (a.action === "Instalação" && b.action !== "Instalação") return -1
    if (a.action === "Remoção" && b.action !== "Remoção") return 1
    return a.code.localeCompare(b.code)
  })

  let html = generateHtml({
    events: cleanEvents,
    filesRead
  })

  let outFM = FileManager.iCloud()
  let dir = outFM.documentsDirectory()
  let path = outFM.joinPath(dir, `hooking_result_${Date.now()}.html`)

  outFM.writeString(path, html)

  await alertMsg(
    "Hooking finalizado",
    `Arquivos lidos: ${filesRead}\nEventos únicos: ${cleanEvents.length}`
  )

  QuickLook.present(path)
}

await main()
