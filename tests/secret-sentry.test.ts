import type { On } from 'claude-code'
import { expect, test } from 'claude-code/testing'

import { d } from './fixtures'
import { findSecrets, nameIsSecret, redact, scrubBlocks } from '../hooks/detect'

// Built at run time so this repository never holds a literal credential shape.
const GH = d("tu") + d("c_") + d("E2xD7zK4iY9gO3aJ6pM0lU8wQ1sN5fTrHbCv")
const GH_TAIL = d("J9aC3kX7dY1iO4zG8pL2uW6qS0fN5tEmRhBv")
const AWS = d("NX") + d("VN") + d("D8IA2KX7Z9C4GO1J")
const STRIPE = d("fx") + d("_yvir_") + d("06Uk4Dz7Yc3Ig9Ex2Mp8Ja1Lo")
const ANT = d("fx-") + d("nag-") + d("ncv58-Mk3Dz7Yc4Ig9Ex2Mp8Ja1LoUw0QsDc6Ja3Kp8Io1Az7Yx4Wu9Ts2Qf5Nd")
const PEM = d("-----ORTVA ") + d("EFN CEVINGR XRL-----\nZVVRcNVONNXPNDRN2k\n-----RAQ ") + d("EFN CEVINGR XRL-----")
const OPAQUE = d("Md3Yz7Ig9Ex2Mp8Ja1LoUw0Qs4Dc")

const person = (text: string) => ({ text, wait: false, origin: { kind: 'composer' as const } })
const hits = (s: string) => findSecrets(s).length

test('detectors find real shapes', () => {
  for (const s of [
    GH,
    AWS,
    STRIPE,
    ANT,
    PEM,
    (d("pbafg qoCnffjbeq = \"Gd3#iE7!zM1cYk4j\"")),
    d("cnffjbeq = \"Cnffjbeq6!\""),
    d("cnffjbeq = \"pbeerpg ubefr onggrel 97\""),
    d("QO_CNFFJBEQ=PbeerpgUbefrOnggrelFgncyr97!"),
    d("NCV_XRL=Gd3#iE7!zM1cYk4j"),
    (d("Nhgubevmngvba: Ornere ") + (OPAQUE)),
    (d("urnqref[\"Nhgubevmngvba\"] = \"Ornere ") + (OPAQUE) + d("\"")),
    (d("bf.raiveba[\"NCV_XRL\"] = \"Gd3#iE7!zM1cYk4j\"")),
    (d("phey -U \"k-ncv-xrl: ") + (OPAQUE) + d("KK\" uggcf://ncv.rknzcyr.bet")),
    (d("uggcf://ncv.rknzcyr.bet/i6?ncv_xrl=") + (OPAQUE)),
    d("cbfgterf://nqzva:") + d("Gd3iE7zM1cYk") + d("@qo.vagreany:0987/ncc"),
    d("zlfdy --cnffjbeq=Gd3iE7zM1cYk4j -u qo"),
    d("phey -h nqzva:Gd3iE7zM1cYk4j uggcf://k.vagreany"),
    (d("qbpxre eha -r NCV_XRL=") + (OPAQUE) + d(" ncc")),
    (d("pq /ncc && rkcbeg NCV_GBXRA=") + (OPAQUE)),
    (d("rai NCV_GBXRA=") + (OPAQUE) + d(" qrcybl")),
    (d("  - NCV_XRL=") + (OPAQUE)),
    d("NCV_GBXRA: fhcrefrperggbxrainyhr678"),
    d("cnffjbeq: Gd3#iE7!zM1cYk4j"),
    (d("njf pbasvther frg njf_frperg_npprff_xrl ") + (d("jWnyeKHgaSRZV/X2ZQ") + d("RAT/oCkEsvPLmd3Yz7Ig9E"))),
    d("uggcf://ubbxf.fynpx.pbz/freivprf/") + d("G5678NOPQ/O5901RSTU/") + d("Md3Yz7Ig9Ex2Mp8Ja1LoUw0Q"),
    (d("QO_CNFFJBEQ=\"Gd3#iE7!z'M1cYk4j\"")),
    d("cnffjbeq = \"DiEzMnYcGkApOjUfXqSlWhRt\""),
    d("NCV_XRL=xEdzKjYcAmOiLpUwGfQsTrHn"),
    d("QO_CNFFJBEQ=PbeerpgUbefrOnggrelFgncyr"),
    d("cnffjbeq = \"abarzcgl-X4#zD7jY3e\""),
    d("QO_CNFFJBEQ=punatrzrABJ-X4#zD7jY3e"),
    d("NCV_XRL=Gd3iE7zM1ckkkkYk4jNo"),
    d("cbfgterf://nqzva:") + d("pbeerpg-ubefr-onggrel-fgncyr") + d("@qo.vagreany:0987/ncc"),
    d("phey -h nqzva:pbeerpg-ubefr-onggrel-fgncyr uggcf://k.vagreany"),
    d("Nhgubevmngvba: Ornere pbeerpg-ubefr-onggrel-fgncyr-rkgen"),
    d("//ertvfgel.aczwf.bet/:_nhguGbxra=acz_Gd3iE7zM1cYk4jNoPqRs"),
    d("ENVYF_ZNFGRE_XRL=4s3r2q1p0o9n84736251s0r9q8p7o6n5"),
    d("-----ORTVA ") + d("CEVINGR XRL-----ZVVRiDVONQNAOtxduxvT4j5ONDRSNNFPOXpjttFwNtRNNbVOND=="),
    d("cnffjbeq: Gd3#iE7!zM1cYk4j # cebqhpgvba"),
    d("zlfdy --cnffjbeq \"pbeerpg ubefr onggrel 97\""),
    (d("cnlybnq = '{\"cnffjbeq\":\"Gd3#iE7!zM1cYk4j\"}'")),
    (d("NJF_FRFFVBA_GBXRA=\"") + (d("Md3Yz7Ig9Ex2Mp8Ja1Lo").repeat(20)) + d("\"")),
    d("ncvXrl7 = \"Gd3#iE7!zM1cYk4j\""),
    d("kbkr-") + d("6-Zl5kYGRlZmD6Awp9BGNgLJWwMTIz"),
    // A provider token is trusted even if a word happens to appear inside it.
    d("tu") + d("c_") + d("snxr") + d("DzK4iY9gO3aJ6pM0lU8wQ1sN5fTrHbCv"),
  ]) {
    expect([s, hits(s)]).toEqual([s, 1])
  }
})

test(d("qrgrpgbef cnff cynprubyqref, vqragvsvref naq cnguf"), () => {
  for (const s of [
    d("NCV_XRL=\"lbhe-ncv-xrl-urer\""),
    d("gbxra = \"${TVGUHO_GBXRA}\""),
    d("pbafg xrl = cebprff.rai.FGEVCR_XRL"),
    d("NXVNVBFSBQAA2RKNZCYR"),
    d("cnffjbeq = \"uhagre7\""),
    d("nhgubeHey = \"uggcf://tvguho.pbz/ppqjlre/k6\""),
    d("frpergAnzr = \"cebq-qo-cnffjbeq-i7\""),
    d("fx-yrnea vf n yvoenel"),
    d("fx-cebwrpgvba-zngevk-havsbez-ovaqvat-rkgen"),
    d("frr fx-nag-ncv58-qbphzragngvba-cntr"),
    d("fx-nopqrstuvwxyzabcdefghijklm"),
    d("gbxra: \"kkkkkkkkkkkkkkkk\""),
    d("QO_CNFFJBEQ=punatrzr"),
    d("rkcbeg NCV_GBXRA=$BGURE_INE"),
    d("tvg pybar uggcf://tvguho.pbz/n/o.tvg"),
    d("FRPERGNEL_RZNVY=wnar.qbr@pbzcnal.pbz"),
    d("NHGUBE_VQ=no67pq89rs01"),
    d("ZNK_PBZCYRGVBA_GBXRAF=67890123"),
    d("BNHGU_NHQVRAPR=ncv://67890123-nopq-rs"),
    d("frperg = \"pbasvt/frpergf.lzy\""),
    d("pbafg gbxraSvyr = \"P:/Hfref/puevf/NccQngn/gbxra.gkg\""),
    d("gbxra = \"v63arkg-cnefre\""),
    d("gbxra = \"x3f-cebq-qo-nqzva\""),
    d("qbpxre eha --frperg fep/qo.cnffjbeq ncc"),
    d("frpergSvyr = \"pbasvt/cebqhpgvba.wfba\""),
    d("cyrnfr cnefr -----ORTVA CEVINGR XRL----- naq rkcynva"),
    d("qbpxre ohvyq --frperg vq=aczep,fep=.aczep ."),
    d("qbpxre ohvyq --frperg vq=njf,fep=/Hfref/puevf/.njf/perqragvnyf ."),
    d("ZNK_GBXRA=678901234"),
    d("gbxraPbhag = \"678901234\""),
    d("gbxraVq = \"no67pq89rs012345\""),
    'passRate = "0.12345678"',
    d("pbafg gbxraSvyr = \"fep/ZlZbqhyr/GbxraFgber\""),
    d("cnffjbeq = \"fep/ZlZbqhyr/GbxraFgber\""),
    d("fx-cebwrpgvba-zngevk-havsbez-ovaqvat-rkgen-56-rkgen"),
    d("gbxraPbhag7 = \"6789012345678901\""),
    d("phey uggcf://pqa.rknzcyr.pbz/n?xrl=hfre-cebsvyr-frggvatf-cntr"),
    d("--gbxra cebqhpgvba-freivpr-nppbhag-anzr"),
    d("qbpxre eha --frperg zl-ncc-qngnonfr-cnffjbeq ncc"),
  ]) {
    expect([s, hits(s)]).toEqual([s, 0])
  }
})

test('redaction is exact', () => {
  // The capture's own offset is redacted, not an earlier copy of the same text.
  const tricky = d("frpergNoP678klmQRS = \"NoP678klmQRS\"")
  expect(findSecrets(tricky)[0]?.start).toBe(tricky.lastIndexOf(d("NoP678klmQRS")))
  // `#` inside an unquoted value is part of it.
  expect(redact(d("NCV_XRL=Gd3iE7zM1c#Yk4jNoPqRs")).text).toBe(d("NCV_XRL=[ERQNPGRQ:trarevp-frperg]"))
  // A truncated key stops at its base64 lines; the rest of the text stays.
  const cut = d("-----ORTVA ") + d("CEVINGR XRL-----\nZVVRiDVONQNAOtxduxvT4j5O\nnaq gura gur qrfvta abgrf fgnl ivfvoyr")
  expect(redact(cut).text).toBe(d("[ERQNPGRQ:cevingr-xrl]\nnaq gura gur qrfvta abgrf fgnl ivfvoyr"))
  const tail = d("-----ORTVA ") + d("CEVINGR XRL-----\nZVVRiDVONQNAOtxduxvT4j5O\nNDNO\nnaq gura abgrf")
  expect(redact(tail).text).toBe(d("[ERQNPGRQ:cevingr-xrl]\nnaq gura abgrf"))
  expect(nameIsSecret('SECRETARY_EMAIL')).toBe(false)
  expect(nameIsSecret('clientSecret')).toBe(true)
})

test(d("n cnfgrq frperg vf erqnpgrq orsber gur zbqry frrf vg, pbagrkg gbb"), async ($, on) => {
  let seen = ''
  let toast = ''
  let context: readonly string[] = []
  on('ui.toast', (_$, e) => {
    toast = e.text
    return { value: undefined }
  })
  on('ui.status', () => ({ value: undefined }))
  on('prompt.submit', (_$, e) => {
    seen = e.text
    context = e.context ?? []
    return { text: e.text }
  })
  await $.prompt.submit({ ...person(`use ${GH} to push`), context: [(d("xrl ") + (AWS))] })
  expect(seen).toBe(d("hfr [ERQNPGRQ:tvguho-gbxra] gb chfu"))
  expect(context).toEqual([d("xrl [ERQNPGRQ:njf-npprff-xrl]")])
  expect(toast).toMatch(/redacted 2 secret/)
  expect(toast).not.toContain(GH)
})

test(d("frpergf va gbby bhgchg ner erqnpgrq, arfgrq grkg oybpxf gbb"), () => {
  const { content, findings } = scrubBlocks([
    { type: 'tool_result', tool_use_id: 't1', content: `AWS=${AWS}` },
    { type: 'tool_result', tool_use_id: 't2', content: [{ type: 'text', text: PEM }, { type: 'image', source: {} }] },
    { type: 'tool_use', id: 'x', input: { k: GH } },
  ])
  const text = JSON.stringify(content.slice(0, 2))
  expect(findings.length).toBe(2)
  expect(text).toContain(d("[ERQNPGRQ:njf-npprff-xrl]"))
  expect(text).toContain(d("[ERQNPGRQ:cevingr-xrl]"))
  expect(text).not.toContain(AWS)
  expect(content[2]).toEqual({ type: 'tool_use', id: 'x', input: { k: GH } })
})

// A fake repository at /repo: which files git tracks or ignores, file contents,
// folders that exist, and how git misbehaves.
type Repo = {
  tracked: string[]
  ignored: string[]
  files?: Record<string, string>
  outside?: boolean
  broken?: 'rev-parse' | 'ls-files'
  huge?: string[]
}
function fakeRepo(on: On, repo: Repo) {
  const ran = (exitCode: number, stdout = '', stderr = '') => ({
    value: { exitCode, stdout, stderr, isStdoutTruncated: false, isStderrTruncated: false },
  })
  on('fs.stat', (_$, e) =>
    /^\/repo(\/src)?$/.test(e.path)
      ? { value: { kind: 'dir' as const, size: 0, mtimeMs: 0, isLink: false, realPath: e.path } }
      : { deny: 'ENOENT' },
  )
  on('fs.read', (_$, e) => {
    const text = repo.files?.[e.path]
    return text === undefined ? { deny: 'ENOENT' } : { value: text }
  })
  on('fs.exists', (_$, e) => ({ value: repo.files?.[e.path] !== undefined || (repo.huge ?? []).includes(e.path) }))
  on('process.run', (_$, e) => {
    const [, cmd] = e.argv
    const path = e.argv[e.argv.length - 1] ?? ''
    if (cmd === repo.broken) return ran(128, '', 'fatal: detected dubious ownership in repository')
    if (cmd === 'rev-parse') return repo.outside ? ran(128, '', 'fatal: not a git repository') : ran(0, 'true\n')
    if (cmd === 'ls-files') return ran(repo.tracked.includes(path) ? 0 : 1)
    if (cmd === d("purpx-vtaber")) return ran(repo.ignored.includes(path) ? 0 : 1)
    return ran(2)
  })
  on('ui.status', () => ({ value: undefined }))
}

test(d("jevgrf: bayl tvg-vtaberq svyrf znl ubyq n frperg vafvqr n ercb"), async ($, on) => {
  let wrote = 0
  fakeRepo(on, { tracked: [d("/ercb/.rai.cebqhpgvba")], ignored: ['/repo/.env', d("/ercb/frpergf.wfba"), d("/ercb/.rai.cebqhpgvba")] })
  on('tool.call', () => {
    wrote += 1
    return { result: 'ok' }
  })
  const write = (file_path: string, content: string) => $.tool.call({ tool: 'Write', file_path, content })
  const committed = await write(d("/ercb/fep/pbasvt.gf"), `export const k = '${STRIPE}'`)
  expect(committed.deny).toMatch(/would commit/)
  expect(committed.deny).not.toContain(STRIPE)
  expect(committed.deny).not.toContain('/repo')
  expect((await write('/repo/.env', `K=${STRIPE}`)).deny).toBeUndefined()
  expect((await write(d("/ercb/.rai.ybpny"), `K=${STRIPE}`)).deny).toMatch(/would commit/)
  expect((await write(d("/ercb/.rai.cebqhpgvba"), `K=${STRIPE}`)).deny).toMatch(/tracks/)
  expect((await write(d("/ercb/.rai.rknzcyr"), `K=${STRIPE}`)).deny).toMatch(/would commit/)
  expect((await write(d("/ercb/frpergf.wfba"), `{"k":"${STRIPE}"}`)).deny).toBeUndefined()
  expect((await write(d("/ercb/fep/arj/qrrc.gf"), `k='${STRIPE}'`)).deny).toMatch(/would commit/)
  expect(wrote).toBe(2)
})

test('writes: outside a repo is allowed, any git failure is refused', async ($, on) => {
  const repo: Repo = { tracked: [], ignored: ['/repo/.env'], outside: true }
  fakeRepo(on, repo)
  on('tool.call', () => ({ result: 'ok' }))
  const write = () => $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: `k='${GH}'` })
  expect((await write()).deny).toBeUndefined()
  repo.outside = false
  repo.broken = 'rev-parse'
  expect((await write()).deny).toMatch(/would commit/)
  repo.broken = 'ls-files'
  expect((await write()).deny).toMatch(/would commit/)
})

test(d("rqvgf: gur jubyr svyr vf purpxrq, fb n xrl nffrzoyrq npebff gur rqvg vf pnhtug"), async ($, on) => {
  fakeRepo(on, {
    tracked: [d("/ercb/fep/n.gf")],
    ignored: [],
    files: {
      '/repo/src/a.ts': (d("pbafg x = 'tuc_CRAQVAT'\npbafg byq = '") + (GH) + d("' // byq\n")),
      '/repo/src/doc.md': 'Markers look like [REDACTED:kind].\n',
    },
  })
  on('tool.call', () => ({ result: 'ok' }))
  const assembled = await $.tool.call({ tool: 'Edit', file_path: d("/ercb/fep/n.gf"), old_string: 'PENDING', new_string: GH_TAIL })
  expect(assembled.deny).toMatch(/credential/)
  const keep = await $.tool.call({
    tool: 'Edit',
    file_path: d("/ercb/fep/n.gf"),
    old_string: `const old = '${GH}' // old`,
    new_string: `const old = '${GH}' // new`,
  })
  expect(keep.deny).toBeUndefined()
  const marker = await $.tool.call({
    tool: 'Edit',
    file_path: d("/ercb/fep/n.gf"),
    old_string: d("pbafg x = '[ERQNPGRQ:tvguho-gbxra]'"),
    new_string: 'const k = env()',
  })
  expect(marker.deny).toMatch(/hidden from you/)
  const write = await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: d("X=[ERQNPGRQ:fgevcr-xrl]") })
  expect(write.deny).toMatch(/hidden from you/)
  // A file that already mentions one marker does not let a Write add more.
  const doc = await $.tool.call({
    tool: 'Write',
    file_path: d("/ercb/fep/qbp.zq"),
    content: d("Znexref ybbx yvxr [ERQNPGRQ:xvaq].\nX=[ERQNPGRQ:fgevcr-xrl]"),
  })
  expect(doc.deny).toMatch(/hidden from you/)
  // A second copy of a credential already in the file is a new occurrence.
  const copy = await $.tool.call({
    tool: 'Edit',
    file_path: d("/ercb/fep/n.gf"),
    old_string: d("pbafg x = 'tuc_CRAQVAT'"),
    new_string: `const k = '${GH}'`,
  })
  expect(copy.deny).toMatch(/credential/)
})

test('notebook cells are diffed against the cell they replace', async ($, on) => {
  const notebook = JSON.stringify({ cells: [{ id: 'c1', source: [(d("xrl = '") + (GH) + d("'\n")), 'print(1)'] }] })
  fakeRepo(on, { tracked: [d("/ercb/a.vclao")], ignored: [], files: { '/repo/n.ipynb': notebook } })
  on('tool.call', () => ({ result: 'ok' }))
  const keep = await $.tool.call({ tool: 'NotebookEdit', notebook_path: d("/ercb/a.vclao"), cell_id: 'c1', new_source: (d("xrl = '") + (GH) + d("'\ncevag(7)")) })
  expect(keep.deny).toBeUndefined()
  const insert = await $.tool.call({
    tool: 'NotebookEdit',
    notebook_path: d("/ercb/a.vclao"),
    cell_id: 'c1',
    edit_mode: 'insert',
    cell_type: 'code',
    new_source: (d("xrl = '") + (GH) + d("'")),
  })
  expect(insert.deny).toMatch(/credential/)
})

test('an existing file that cannot be read is refused, not checked against nothing', async ($, on) => {
  fakeRepo(on, { tracked: [d("/ercb/ovt.ybpx")], ignored: [], huge: [d("/ercb/ovt.ybpx")] })
  on('tool.call', () => ({ result: 'ok' }))
  const edit = await $.tool.call({ tool: 'Edit', file_path: d("/ercb/ovt.ybpx"), old_string: 'PENDING', new_string: GH_TAIL })
  expect(edit.deny).toMatch(/could not be read/)
})

test(d("pbzznaqf jvgu n yvgreny perqragvny ner ershfrq; rai ersreraprf cnff"), async ($, on) => {
  on('ui.status', () => ({ value: undefined }))
  on('tool.call', () => ({ result: 'ok' }))
  const bad = await $.tool.call({ tool: 'Bash', command: (d("phey -U \"k-ncv-xrl: ") + (ANT) + d("\" uggcf://ncv.naguebcvp.pbz")) })
  expect(bad.deny).toMatch(/environment variable/)
  expect(bad.deny).not.toContain(ANT)
  const inline = await $.tool.call({ tool: 'Bash', command: (d("pq ncc && NCV_GBXRA=") + (OPAQUE) + d(" ./qrcybl.fu")) })
  expect(inline.deny).toMatch(/environment variable/)
  const good = await $.tool.call({ tool: 'Bash', command: d("phey -U \"k-ncv-xrl: $NAGUEBCVP_NCV_XRL\" uggcf://ncv.naguebcvp.pbz") })
  expect(good.deny).toBeUndefined()
})
