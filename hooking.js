// HOOKING - MCSettings / MCProfile Scanner

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

function walkDirectory(fm, dir, files = []) {
  let items = fm.listContents(dir)

  for (let item of items) {
    let path = fm.joinPath(dir, item)
    let lower = path.toLowerCase()

    if (fm.isDirectory(path)) {
      walkDirectory(fm, path, files)
    } else if (
      lower.includes("mcsettings") ||
      lower.includes("mcprofile")
    ) {
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

function cleanText(s) {
  return String(s || "")
    .replace(/\u0000/g, "")
    .replace(/[^\x20-\x7EÀ-ÿ]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
}

function normalizeCode(code) {
  return cleanText(code)
    .replace(/^[-_\s]+/, "")
    .replace(/[-_\s]+$/, "")
}

function extractProfileCodes(content, file) {
  let events = []
  let text = cleanText(content)

  let operationRegex = /(install|remove)/gi
  let operations = []
  let op

  while ((op = operationRegex.exec(text)) !== null) {
    operations.push({
      type: op[1].toLowerCase() === "install" ? "Instalação" : "Remoção",
      index: op.index
    })
  }

  let codeRegexes = [
    /([a-f0-9]{40,96}-[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})/g,
    /([a-f0-9]{32,96})/g,
    /((?:com\.)[a-zA-Z0-9._~\-]{4,180})/g,
    /((?:xyz\.)[a-zA-Z0-9._~\-]{4,180})/g
  ]

  for (let regex of codeRegexes) {
    let m

    while ((m = regex.exec(text)) !== null) {
      let code = normalizeCode(m[1])
      if (!code || code.length < 8) continue

      let nearestOp = null
      let nearestDistance = Infinity

      for (let o of operations) {
        let distance = Math.abs(o.index - m.index)
        if (distance < nearestDistance && distance < 1800) {
          nearestDistance = distance
          nearestOp = o
        }
      }

      if (!nearestOp) continue

      events.push({
        action: nearestOp.type,
        code,
        file,
        position: m.index
      })
    }
  }

  return uniqueEvents(events)
}

function uniqueEvents(events) {
  let map = {}

  for (let ev of events) {
    let key = `${ev.action}|${ev.code}`
    if (!map[key]) map[key] = ev
  }

  return Object.values(map)
}

function generateHtml(data) {
  let installed = data.events.filter(e => e.action === "Instalação")
  let removed = data.events.filter(e => e.action === "Remoção")

  function card(ev) {
    let cls = ev.action === "Remoção" ? "remove" : "install"

    return `
      <div class="card">
        <div>
          <span class="tag ${cls}">${ev.action}</span>
          <div class="code">${ev.code}</div>
          <div class="file">${ev.file.split("/").pop()}</div>
        </div>
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
.main-name {
  color:#ffffff;
  font-size:42px;
  font-weight:900;
  letter-spacing:8px;
  text-shadow:0 0 12px #fff, 0 0 22px #777;
  margin-bottom:4px;
}
.credits {
  color:#777;
  font-size:12px;
  letter-spacing:3px;
  margin-bottom:20px;
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
</style>
</head>
<body>

<div class="main-name">${APP_NAME}</div>
<div class="credits">CRÉDITOS: ${CREDIT}<br>${DISCORD}</div>

<div class="section">
  <div class="title">◆ ARQUIVOS ANALISADOS</div>
  <div class="row"><span class="label">MCSettings / MCProfile lidos</span><span class="value">${data.filesRead}</span></div>
  <div class="row"><span class="label">Eventos encontrados</span><span class="value">${data.events.length}</span></div>
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
  <div class="title">◆ TODOS OS EVENTOS (${data.events.length})</div>
  ${data.events.length ? data.events.map(card).join("") : "<p>Nenhum código com install/remove encontrado.</p>"}
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
    let lower = file.toLowerCase()

    if (
      !lower.includes("mcsettings") &&
      !lower.includes("mcprofile")
    ) {
      continue
    }

    let content = readTextSafe(fm, file)
    if (!content) continue

    filesRead++
    allEvents.push(...extractProfileCodes(content, file))
  }

  let cleanEvents = uniqueEvents(allEvents)

  cleanEvents.sort((a, b) => {
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
    `MCSettings/MCProfile lidos: ${filesRead}\nEventos encontrados: ${cleanEvents.length}`
  )

  QuickLook.present(path)
}

await main()
