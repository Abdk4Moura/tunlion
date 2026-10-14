import React from 'react'
import { Ctx, useT, useThemeMode, useNarrow, Mark, Btn, Tag, Section, Card, Line, Row, Seg, Check, Applied, Title, Page, FONT_SANS, FONT_MONO } from './ui.jsx'
import { signIn, getState, act, invite, startCode, cancelCode, codeStatus } from './api.js'
import { rows as toRows, exposure as toExposure, history as toHistory, utc, ago, capWord, GRANTABLE } from './model.js'

const NAV = [['overview', 'Overview'], ['devices', 'Devices and people'], ['codes', 'Codes and invitations'], ['asks', 'Asks'], ['exposure', 'Exposure'], ['history', 'History']]
const PHONE_NAV = [['overview', 'Overview'], ['devices', 'Devices'], ['asks', 'Asks']]

export default function Dashboard() {
  const [T, toggleTheme] = useThemeMode()
  const narrow = useNarrow()
  const [auth, setAuth] = React.useState({ phase: 'signing' })
  const [state, setState] = React.useState(null)
  const [closed, setClosed] = React.useState(false)
  const [screen, setScreen] = React.useState('overview')
  const [sel, setSel] = React.useState(null)
  const [toast, setToast] = React.useState(null)
  const [busy, setBusy] = React.useState(false)
  const [done, setDone] = React.useState([])
  const toastTimer = React.useRef(null)

  const refresh = React.useCallback(async () => {
    try { setState(await getState()); setClosed(false) } catch (e) { setClosed(true) }
  }, [])

  React.useEffect(() => {
    signIn().then((r) => {
      if (r.ok) { setAuth({ phase: 'in' }); refresh() } else setAuth({ phase: 'out', error: r.error })
    })
  }, [refresh])
  React.useEffect(() => {
    if (auth.phase !== 'in') return
    const id = setInterval(refresh, 4000)
    return () => clearInterval(id)
  }, [auth.phase, refresh])
  React.useEffect(() => {
    document.body.style.background = T.bg
    document.documentElement.style.setProperty('--tl-ring', T.ink)
  }, [T])

  const say = (msg, undo, tone) => {
    clearTimeout(toastTimer.current)
    setToast({ msg, undo, tone })
    toastTimer.current = setTimeout(() => setToast(null), undo ? 10000 : 4500)
  }

  // Every change is a local write on this device: it is the one being
  // reached, so it applies here at once.
  const run = async (verb, args, okMsg, undo) => {
    setBusy(true)
    const r = await act(verb, args)
    setBusy(false)
    await refresh()
    if (r.ok) say(okMsg, undo)
    else say(r.error || r.message || 'That did not work.', null, 'bad')
    return r
  }

  const go = (s) => { setScreen(s); setSel(null) }
  const open = (name) => { setSel(name); setScreen('device') }

  const ctx = { T, narrow }
  if (auth.phase !== 'in') {
    return (
      <Ctx.Provider value={ctx}>
        <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: T.bg, color: T.ink, fontFamily: FONT_SANS, padding: 16 }}>
          <div style={{ maxWidth: 440, display: 'grid', gap: 14, justifyItems: 'start' }}>
            <Mark size={36} anim={auth.phase === 'signing' ? 'pulse' : undefined} />
            <h1 style={{ margin: 0, fontSize: 24 }}>{auth.phase === 'signing' ? 'Opening the dashboard' : 'This link did not open the dashboard'}</h1>
            {auth.error && <p role="alert" style={{ margin: 0, color: T.sub, lineHeight: 1.5 }}>{auth.error}</p>}
          </div>
        </div>
      </Ctx.Provider>
    )
  }

  const rs = state ? toRows(state) : []
  const ex = state ? toExposure(state, rs, done) : []
  const hi = ex.filter((x) => x.risk === 'high').length
  const asks = state ? state.requests : []
  const A = { state, rs, ex, asks, go, open, run, say, busy, setDone, done, refresh }
  const Screen = { overview: Overview, devices: Devices, device: Device, codes: Codes, asks: Asks, exposure: Exposure, history: History }[screen]
  const cur = screen === 'device' ? 'devices' : screen
  const badge = (k) => (k === 'asks' && asks.length ? <span style={{ marginLeft: 'auto', display: 'inline-flex', gap: 5, alignItems: 'center' }}><Mark size={13} anim="knock" /><span style={{ font: '600 11px ' + FONT_MONO, background: T.ink, color: T.inv, borderRadius: 8, padding: '2px 6px' }}>{asks.length}</span></span>
    : k === 'exposure' && hi ? <span style={{ marginLeft: 'auto', font: '600 11px ' + FONT_MONO, border: '1px solid ' + T.bad, color: T.bad, borderRadius: 8, padding: '1px 6px' }}>{hi}</span> : null)

  const body = (
    <main style={{ flex: 1, minWidth: 0, minHeight: 0, overflow: 'auto' }}>
      {closed && <div role="alert" style={{ padding: narrow ? '10px 16px' : '10px 36px', borderBottom: '1px solid ' + T.bad, color: T.bad, fontSize: 14 }}>The dashboard closed. Run <code>tunlion dashboard</code> again for a new link.</div>}
      {state && !state.daemon.answering && <div style={{ padding: narrow ? '10px 16px' : '10px 36px', borderBottom: '1px solid ' + T.rule, color: T.sub, fontSize: 13.5 }}>The background service is not answering, so asks and who is online can't be shown. Run <code>tunlion up --detach</code>.</div>}
      {state ? <Screen A={A} sel={sel} /> : <Page><Title>Loading</Title></Page>}
    </main>
  )
  const overlay = toast && (
    <div role="status" style={{ position: 'fixed', left: '50%', bottom: narrow ? 84 : 24, transform: 'translateX(-50%)', background: toast.tone === 'bad' ? T.bad : T.ink, color: T.inv, padding: '11px 16px', borderRadius: 8, fontSize: 14, maxWidth: 'min(640px, 92vw)', boxShadow: '0 10px 30px -10px rgba(0,0,0,.4)', display: 'flex', gap: 14, alignItems: 'center', zIndex: 6, whiteSpace: 'pre-line' }}>
      <span>{toast.msg}</span>
      {toast.undo && <button type="button" onClick={() => { const u = toast.undo; setToast(null); u() }} className="tl-focus" style={{ border: 0, background: 'none', color: T.inv, textDecoration: 'underline', textUnderlineOffset: 3, font: '700 14px ' + FONT_SANS, cursor: 'pointer', padding: '10px 6px', minHeight: 44, flexShrink: 0 }}>Undo</button>}
    </div>
  )

  return (
    <Ctx.Provider value={ctx}>
      {narrow ? (
        <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', background: T.bg, color: T.ink, fontFamily: FONT_SANS }}>
          <header style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 16px', borderBottom: '1px solid ' + T.rule }}>
            <Mark size={22} /><b style={{ fontSize: 17, letterSpacing: '-.02em' }}>tunlion</b>
            <span style={{ fontSize: 12.5, color: T.sub, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>on {state ? state.me.name : ''}</span>
            <button type="button" onClick={toggleTheme} className="tl-focus" style={{ marginLeft: 'auto', border: '1px solid ' + T.rule, background: 'none', color: T.sub, borderRadius: 6, padding: '0 12px', font: '500 12px ' + FONT_MONO, minHeight: 44 }}>{T.mode === 'light' ? 'Dark' : 'Light'}</button>
          </header>
          {body}
          <nav aria-label="Dashboard" style={{ display: 'flex', borderTop: '1px solid ' + T.rule, padding: '2px 8px 12px' }}>
            {PHONE_NAV.map(([k, l]) => <button key={k} type="button" onClick={() => go(k)} aria-current={cur === k ? 'page' : undefined} className="tl-focus" style={{ flex: 1, minHeight: 50, border: 0, background: 'none', color: cur === k ? T.ink : T.sub, font: `${cur === k ? 600 : 500} 13px ${FONT_SANS}`, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, cursor: 'pointer' }}>{l}{k === 'asks' && asks.length > 0 && <span style={{ font: '600 11px ' + FONT_MONO, background: T.ink, color: T.inv, borderRadius: 8, padding: '2px 6px' }}>{asks.length}</span>}</button>)}
          </nav>
          {overlay}
        </div>
      ) : (
        <div style={{ height: '100vh', display: 'flex', background: T.bg, color: T.ink, fontFamily: FONT_SANS }}>
          <aside style={{ width: 236, flexShrink: 0, borderRight: '1px solid ' + T.rule, padding: '22px 14px', display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '0 10px 4px' }}><Mark size={26} anim={busy ? 'pulse' : undefined} /><b style={{ fontSize: 20, letterSpacing: '-.025em' }}>tunlion</b></div>
            <div style={{ fontSize: 12.5, color: T.sub, padding: '0 10px 16px' }}>dashboard on {state ? state.me.name : ''}{state && state.me.owner ? ' · owner' : ''}</div>
            <nav aria-label="Dashboard" style={{ display: 'grid', gap: 4 }}>
              {NAV.map(([k, l]) => <button key={k} type="button" onClick={() => go(k)} aria-current={cur === k ? 'page' : undefined} className="tl-focus" style={{ display: 'flex', alignItems: 'center', gap: 8, minHeight: 40, padding: '0 10px', borderRadius: 7, border: 0, background: cur === k ? T.soft : 'transparent', color: cur === k ? T.ink : T.sub, font: `${cur === k ? 600 : 500} 14px ${FONT_SANS}`, cursor: 'pointer', textAlign: 'left' }}>{l}{badge(k)}</button>)}
            </nav>
            <div style={{ marginTop: 'auto', display: 'grid', gap: 10, padding: '0 10px' }}>
              <span style={{ fontSize: 12, color: T.sub, lineHeight: 1.45 }}>No account. Being the owner means holding the owner key; recovery is your recovery phrase.</span>
              <button type="button" onClick={toggleTheme} className="tl-focus" style={{ justifySelf: 'start', border: '1px solid ' + T.rule, background: 'none', color: T.sub, borderRadius: 6, padding: '6px 10px', font: '500 12px ' + FONT_MONO, cursor: 'pointer', minHeight: 32 }}>{T.mode === 'light' ? 'Dark' : 'Light'}</button>
            </div>
          </aside>
          {body}
          {overlay}
        </div>
      )}
    </Ctx.Provider>
  )
}

function AskCard({ a, A }) {
  const { T } = useT()
  const [dur, setDur] = React.useState('1d')
  const me = A.state.me.name
  return (
    <div data-testid="ask" style={{ display: 'grid', gap: 10, padding: '14px 0', borderBottom: '1px solid ' + T.rule }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <Mark size={18} anim="knock" />
        <span style={{ fontSize: 15, flex: 1, minWidth: 200 }}><b>{a.peer}</b> asks for {capWord(a.capability)} on {me}</span>
        <span style={{ fontSize: 12.5, color: T.sub }}>{a.ago}</span>
      </div>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ minWidth: 240 }}><Seg label="For how long" value={dur} onChange={setDur} options={[['1h', '1 hour'], ['1d', '1 day'], ['7d', '7 days'], ['30d', '30 days']]} /></div>
        <Btn kind="pri" small testid="ask-accept" onClick={() => A.run('approve', { id: a.id, cap: a.capability, for: dur }, `Applied on ${me}. ${a.peer} can use ${capWord(a.capability)} here for ${dur}.`)}>Accept</Btn>
        <Btn small onClick={() => A.run('deny', { id: a.id }, 'Declined. Nothing changed.')}>Decline</Btn>
      </div>
      <span style={{ fontSize: 12.5, color: T.sub }}>{me} is the device being reached, so Accept applies here at once.</span>
    </div>
  )
}

function Overview({ A }) {
  const { T, narrow } = useT()
  const { state, rs, ex, asks } = A
  const live = rs.filter((r) => r.group !== 'gone')
  const online = live.filter((r) => r.online).length
  const people = live.filter((r) => r.group === 'remembered').length
  const soon = live.filter((r) => r.until && r.until - state.now < 7 * 86400)
  const hi = ex.filter((x) => x.risk === 'high').length
  const stat = (n, l, to) => (
    <button type="button" onClick={() => A.go(to)} className="tl-focus" style={{ textAlign: 'left', border: '1px solid ' + T.rule, background: T.surf, borderRadius: 10, padding: '16px 18px', cursor: 'pointer', color: T.ink, display: 'grid', gap: 4, font: 'inherit' }}>
      <span style={{ font: `600 ${narrow ? 28 : 34}px/1 ${FONT_SANS}`, letterSpacing: '-.02em' }}>{n}</span><span style={{ fontSize: 13.5, color: T.sub }}>{l} →</span>
    </button>
  )
  return (
    <Page>
      <Title sub={`Served by ${state.me.name}${state.me.owner ? ', which holds your owner key' : ''}. Every change here is written by ${state.me.name}, the device being reached.`}>Overview</Title>
      {asks.length > 0 && <Card><Section>Waiting on you</Section>{asks.map((a) => <AskCard key={a.id} a={a} A={A} />)}</Card>}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 12 }}>
        {stat(online, 'devices online', 'devices')}{stat(people, narrow ? 'people' : 'people with access', 'devices')}{stat(asks.length, narrow ? 'asks' : 'asks waiting', 'asks')}
      </div>
      <Card>
        <Section>Ending soon · next 7 days</Section>
        {!soon.length && <div style={{ fontSize: 14, color: T.sub, padding: '10px 0' }}>Nothing ends in the next 7 days.</div>}
        {soon.map((r) => (
          <Row key={r.name}>
            <button type="button" onClick={() => A.open(r.name)} className="tl-focus" style={{ flex: 1, minWidth: 220, textAlign: 'left', border: 0, background: 'none', color: T.ink, cursor: 'pointer', padding: 0, display: 'grid', gap: 3, font: 'inherit' }}><b style={{ fontSize: 15 }}>{r.name}</b><span style={{ fontSize: 13, color: T.sub }}>{r.caps.map(capWord).join(', ')} on {state.me.name} · ends {utc(r.until)}</span></button>
            <span style={{ fontSize: 13, color: T.sub }}>Ends by itself.</span>
          </Row>
        ))}
      </Card>
      <button type="button" onClick={() => A.go('exposure')} className="tl-focus" style={{ textAlign: 'left', border: '1.5px solid ' + (hi ? T.bad : T.rule), background: T.surf, borderRadius: 10, padding: '14px 18px', cursor: 'pointer', color: T.ink, display: 'flex', alignItems: 'center', gap: 12, font: 'inherit' }}>
        <span style={{ flex: 1, display: 'grid', gap: 3 }}><b style={{ fontSize: 15 }}>Exposure</b><span style={{ fontSize: 13.5, color: T.sub }}>{ex.length ? `${ex.length} to look at${hi ? `, ${hi} high` : ''}` : 'Nothing needs a look'}</span></span><span style={{ color: T.sub }}>Review →</span>
      </button>
      <Card>
        <Section right={<button type="button" onClick={() => A.go('history')} className="tl-focus" style={{ border: 0, background: 'none', color: T.sub, fontSize: 13, cursor: 'pointer', minHeight: 32 }}>History →</button>}>Recent activity</Section>
        {toHistory(state).slice(0, 5).map((h, i) => <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid ' + T.rule, font: '500 12.5px/1.45 ' + FONT_MONO, color: T.sub, overflowWrap: 'anywhere' }}>{h.text}</div>)}
        {!state.history.length && <div style={{ fontSize: 14, color: T.sub, padding: '10px 0' }}>Nothing logged yet.</div>}
      </Card>
    </Page>
  )
}

function Devices({ A }) {
  const { T, narrow } = useT()
  const [q, setQ] = React.useState('')
  const [picked, setPicked] = React.useState([])
  const [confirm, setConfirm] = React.useState(false)
  const qq = q.trim().toLowerCase()
  const match = (r) => !qq || (r.name + ' ' + r.line).toLowerCase().includes(qq)
  const groups = [['mine', 'My devices'], ['remembered', 'Remembered'], ['gone', 'Ended or cut off']]
  const pick = (n) => setPicked((p) => (p.includes(n) ? p.filter((x) => x !== n) : [...p, n]))
  const cutAll = async () => {
    const names = picked.slice()
    setConfirm(false); setPicked([])
    for (const n of names) await A.run('cut', { device: n }, `${names.join(', ')} cut off.`)
  }
  const onlinePicked = picked.filter((n) => (A.rs.find((r) => r.name === n) || {}).online)
  return (
    <Page>
      <Title sub={`Everything that can reach ${A.state.me.name}, and what it may do here.`}>Devices and people</Title>
      <input className="tl-input" aria-label="Search devices and people" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search names and access" style={{ minHeight: 46, border: '1.5px solid ' + T.ink, borderRadius: 8, padding: '0 14px', font: '15px ' + FONT_SANS, background: T.surf, color: T.ink }} />
      {picked.length > 0 && (
        <div style={{ position: 'sticky', top: 0, zIndex: 2, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', padding: '10px 14px', borderRadius: 8, background: T.ink, color: T.inv }}>
          <b style={{ fontSize: 14 }}>{picked.length} selected</b>
          <span style={{ fontSize: 12.5, opacity: 0.85 }}>Bulk actions only narrow.</span>
          <span style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            {confirm
              ? <><span style={{ fontSize: 13.5, alignSelf: 'center' }}>{onlinePicked.length ? `${onlinePicked.join(', ')} ${onlinePicked.length === 1 ? 'is' : 'are'} online; their connections close. ` : ''}Cut off {picked.length}?</span><button type="button" className="tl-focus" onClick={cutAll} style={{ minHeight: 44, padding: '0 12px', borderRadius: 6, border: 0, background: T.inv, color: T.ink, font: '600 13px ' + FONT_SANS, cursor: 'pointer' }}>Cut off</button><button type="button" className="tl-focus" onClick={() => setConfirm(false)} style={{ minHeight: 44, padding: '0 10px', border: 0, background: 'none', color: T.inv, textDecoration: 'underline', cursor: 'pointer' }}>Keep</button></>
              : <><button type="button" className="tl-focus" onClick={() => setConfirm(true)} style={{ minHeight: 44, padding: '0 12px', borderRadius: 6, border: 0, background: T.inv, color: T.ink, font: '600 13px ' + FONT_SANS, cursor: 'pointer' }}>Cut off {picked.length}</button><button type="button" className="tl-focus" onClick={() => setPicked([])} style={{ minHeight: 44, padding: '0 10px', border: 0, background: 'none', color: T.inv, textDecoration: 'underline', cursor: 'pointer' }}>Clear</button></>}
          </span>
        </div>
      )}
      {!A.rs.length && <Card><div style={{ fontSize: 14.5, color: T.sub }}>No devices yet. Make an invitation under Codes and invitations, or run <code>tunlion add</code>.</div></Card>}
      {groups.map(([g, label]) => {
        const list = A.rs.filter((r) => r.group === g && match(r))
        if (!list.length) return null
        return (
          <Card key={g}>
            <Section>{label} · {list.length}</Section>
            {list.map((r) => (
              <div key={r.name} data-testid="device-row" style={{ display: 'flex', gap: 12, alignItems: 'flex-start', padding: '12px 0', borderBottom: '1px solid ' + T.rule }}>
                {g === 'gone' ? <span style={{ width: 22, flexShrink: 0 }} /> : <input type="checkbox" aria-label={'Select ' + r.name} checked={picked.includes(r.name)} onChange={() => pick(r.name)} style={{ width: 22, height: 22, marginTop: 2, accentColor: T.ink, flexShrink: 0 }} />}
                <button type="button" onClick={() => A.open(r.name)} className="tl-focus" style={{ flex: 1, minWidth: 0, textAlign: 'left', border: 0, background: 'none', padding: 0, color: T.ink, cursor: 'pointer', display: 'grid', gap: 6, font: 'inherit' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}><b style={{ fontSize: 15 }}>{r.name}</b>{r.online != null && <Tag tone={r.online ? 'ok' : 'n'}>{r.online ? 'online' : 'idle'}</Tag>}<span style={{ fontSize: 12.5, color: T.sub }}>{r.online ? 'online now' : 'last seen ' + ago(A.state.now, r.lastSeen)}</span></span>
                  <span style={{ font: '500 12.5px/1.45 ' + FONT_MONO, color: T.sub, overflowWrap: 'anywhere' }}>{r.line}</span>
                </button>
              </div>
            ))}
          </Card>
        )
      })}
    </Page>
  )
}

function Device({ A, sel }) {
  const { T, narrow } = useT()
  const [confirm, setConfirm] = React.useState(null)
  const r = A.rs.find((x) => x.name === sel)
  const me = A.state.me.name
  if (!r) return <Page><Title>Forgotten</Title><div><Btn onClick={() => A.go('devices')}>Devices and people</Btn></div></Page>
  const gone = r.group === 'gone'
  const hist = toHistory(A.state).filter((h) => h.text.includes(r.name)).slice(0, 12)
  const grant = (c) => A.run('grant', { device: r.name, cap: c }, `Applied on ${me}. ${r.name} can use ${capWord(c)} here.`, () => A.run('revoke-cap', { device: r.name, cap: c }, `Undone: ${r.name} can no longer use ${capWord(c)} here.`))
  const revokeCap = (c, until) => A.run('revoke-cap', { device: r.name, cap: c }, `${r.name} can no longer use ${capWord(c)} on ${me}.`, until ? null : () => A.run('grant', { device: r.name, cap: c }, `Restored: ${r.name} can use ${capWord(c)} here.`))
  const cut = () => A.run('cut', { device: r.name }, `${r.name} cut off. Undo restores access, not connections.`, () => A.run('restore', { device: r.name }, `${r.name} restored, as it was.`))
  return (
    <Page>
      <button type="button" onClick={() => A.go('devices')} className="tl-focus" style={{ alignSelf: 'flex-start', border: 0, background: 'none', color: T.sub, fontSize: 14, cursor: 'pointer', padding: '0 4px', minHeight: 44 }}>← Devices and people</button>
      <Title right={<span style={{ display: 'flex', gap: 8 }}>{r.online != null && <Tag tone={r.online ? 'ok' : 'n'}>{r.online ? 'online' : 'idle'}</Tag>}</span>} sub={r.online ? 'online now' : 'last seen ' + ago(A.state.now, r.lastSeen)}>{r.name}</Title>
      <Line>{r.line}</Line>
      {r.caveats.length > 0 && <div style={{ fontSize: 13.5, color: T.sub }}>{r.caveats.join(' ')}</div>}
      {!gone && (
        <div style={{ display: 'grid', gridTemplateColumns: narrow ? '1fr' : '1fr 1fr', gap: 16 }}>
          <Card testid="caps-here">
            <Section>{r.name} can use {me} for</Section>
            {GRANTABLE.map((c) => {
              const row = r.live.find((x) => x.action === c)
              return (
                <Row key={c}>
                  <span style={{ display: 'grid', gap: 2 }}><span style={{ fontSize: 15, color: row ? T.ink : T.sub }}>{capWord(c)}</span>{row && <span style={{ fontSize: 12.5, color: T.sub }}>{row.source}{row.valid_until ? ' · until ' + utc(row.valid_until) : ' · no end time'}</span>}</span>
                  {row && /ceiling/.test(row.source || '')
                    ? <span style={{ fontSize: 12.5, color: T.sub, maxWidth: 230, textAlign: 'right' }}>Came with its invitation. Cut it off to take this away.</span>
                    : row
                    ? <Btn kind="ghost" small label={`Remove ${capWord(c)}`} onClick={() => revokeCap(c, row.valid_until)}>Remove</Btn>
                    : confirm === c
                      ? <span style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}><span style={{ fontSize: 12.5, color: T.bad, maxWidth: 260 }}>A shell lets {r.name} do anything you can on {me}.</span><Btn kind="dan" small onClick={() => { setConfirm(null); grant(c) }}>Allow shell</Btn><Btn kind="ghost" small onClick={() => setConfirm(null)}>Keep off</Btn></span>
                      : <Btn small label={`Allow ${capWord(c)}`} onClick={() => (c === 'shell' ? setConfirm('shell') : grant(c))}>Allow</Btn>}
                </Row>
              )
            })}
            <div style={{ fontSize: 12.5, color: T.sub, marginTop: 10 }}>{me} is the device being reached, so these apply here at once.</div>
          </Card>
          <Card>
            <Section>{me} can use {r.name} for</Section>
            <div style={{ fontSize: 14, color: T.sub, padding: '10px 0', lineHeight: 1.5 }}>That is written on {r.name}, not here. Open the dashboard on {r.name} to see or change it.</div>
          </Card>
        </div>
      )}
      {hist.length > 0 && !narrow && <Card><Section>History · from {me}'s log</Section>{hist.map((h, i) => <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid ' + T.rule, font: '500 12.5px/1.45 ' + FONT_MONO, color: T.sub, overflowWrap: 'anywhere' }}>{h.text}</div>)}</Card>}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        {gone
          ? (r.state === 'revoked' ? <Btn kind="pri" onClick={() => A.run('restore', { device: r.name }, `${r.name} restored, as it was.`)}>Restore</Btn> : <span style={{ fontSize: 13.5, color: T.sub }}>Its access ended. To let it back in, make a new invitation.</span>)
          : confirm === 'cut'
            ? <><span style={{ fontSize: 14 }}>{r.name} is online now. Cut it off and close its connections? Undo restores access, not the connections.</span><Btn kind="dan" onClick={() => { setConfirm(null); cut() }}>Cut off and close</Btn><Btn onClick={() => setConfirm(null)}>Keep</Btn></>
            : <Btn kind="dan" testid="cut" onClick={() => (r.online ? setConfirm('cut') : cut())}>Cut off</Btn>}
        {confirm === 'forget'
          ? <><span style={{ fontSize: 14 }}>Forget {r.name} on {me}? This can't be undone; you would pair again to get it back.</span><Btn kind="dan" onClick={() => { setConfirm(null); A.run('forget', { device: r.name }, `Forgot ${r.name} on ${me}.`).then(() => A.go('devices')) }}>Forget</Btn><Btn onClick={() => setConfirm(null)}>Keep</Btn></>
          : <Btn kind="ghost" onClick={() => setConfirm('forget')}>Forget</Btn>}
      </div>
    </Page>
  )
}

const TEMPLATES = [
  { id: 'guest', t: 'Guest gets files', d: 'Someone can send files here until a date. Nothing else.', f: { kind: 'person', name: 'guest', allow: ['transfer'], expires: '3d' } },
  { id: 'shell', t: 'Lend a shell', d: 'A shell on this machine until a date, for one person.', f: { kind: 'person', name: 'friend', allow: ['transfer', 'shell'], expires: '7d' } },
  { id: 'family', t: 'Family phone', d: 'Joins your devices with files only. No shell.', f: { kind: 'device', name: 'family-phone', allow: ['transfer'], expires: '30d' } },
  { id: 'ci', t: 'CI runner', d: 'A one-time key a machine uses to join, with an expiry.', f: { kind: 'runner', name: 'ci-runner', allow: [], expires: '7d' } },
]
const ENDS = [['1d', 'Tomorrow'], ['3d', '3 days'], ['7d', '7 days'], ['30d', '30 days'], ['90d', '90 days']]
const ENDS_WORD = Object.fromEntries(ENDS)

function Codes({ A }) {
  const { T, narrow } = useT()
  const me = A.state.me.name
  const [f, setF] = React.useState({ ...TEMPLATES[0].f, tmpl: TEMPLATES[0].t })
  const [made, setMade] = React.useState(null)
  const [err, setErr] = React.useState(null)
  const set = (p) => setF((x) => ({ ...x, ...p }))
  const toggleCap = (c) => set({ allow: f.allow.includes(c) ? f.allow.filter((x) => x !== c) : [...f.allow, c] })
  const owner = A.state.me.owner
  const kinds = [['person', 'A person'], ...(owner ? [['device', 'One of my devices']] : []), ['runner', 'A machine (key)']]
  const capsWord = f.kind === 'runner' ? 'nothing until it joins' : (f.allow.length ? f.allow.map(capWord).join(', ') : 'nothing')
  const ceiling = f.kind === 'runner'
    ? `A machine can use this key once to enrol, until ${ENDS_WORD[f.expires]} from now. It joins as a temporary key, not a member.`
    : f.kind === 'device'
      ? `It joins your devices with ${capsWord} on ${me}, for ${ENDS_WORD[f.expires]}. Shell stays off unless you tick it.`
      : `${f.name || 'They'} can join once within ${ENDS_WORD[f.expires]} and then use ${capsWord} on ${me}, until that end.`
  const preview = `${f.kind === 'device' ? 'my device' : 'remembered'} · ${f.name || 'they'} can use ${me} for: ${f.allow.length && f.kind !== 'runner' ? f.allow.map(capWord).join(', ') : 'nothing'} · ends ${ENDS_WORD[f.expires].toLowerCase()} after joining`
  const make = async () => {
    setErr(null)
    const r = await invite({ kind: f.kind, name: f.name, allow: f.kind === 'runner' ? [] : f.allow, expires: f.expires })
    if (r.ok) { setMade({ text: r.invitation, name: f.name, shown: true }); A.refresh() } else setErr(r.error || r.message || 'That did not work.')
  }
  const copy = async () => {
    try { await navigator.clipboard.writeText(made.text) } catch (e) { /* the save button still works */ }
    setMade({ ...made, text: null, shown: false, how: 'Copied' })
  }
  const save = () => {
    const blob = new Blob([made.text], { type: 'text/plain' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob); a.download = `${made.name}.invite`; a.click()
    setTimeout(() => URL.revokeObjectURL(a.href), 2000)
    setMade({ ...made, text: null, shown: false, how: `Saved as ${made.name}.invite` })
  }
  if (made) return (
    <Page>
      <Title sub={f.tmpl ? `From the template "${f.tmpl}"` : 'From scratch'}>Invitation for {made.name}</Title>
      <Line>{preview}</Line>
      <Card testid="invitation">
        <div style={{ marginBottom: 12 }}><Applied>Made on {me}</Applied></div>
        {made.shown ? (<>
          <pre data-testid="secret" style={{ margin: 0, font: '500 12px/1.5 ' + FONT_MONO, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 200, overflow: 'auto', background: T.soft, padding: 12, borderRadius: 7 }}>{made.text}</pre>
          <div style={{ fontSize: 13.5, color: T.sub, margin: '8px 0 14px' }}>Shown once. Anyone holding it can use it once, until it expires. On their side: <code>tunlion join {made.name}.invite</code>, or paste it at "I have a code or an invitation".</div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}><Btn kind="pri" onClick={save}>Save as a file and hide</Btn><Btn onClick={copy}>Copy and hide</Btn></div>
        </>) : <div style={{ fontSize: 14.5 }}>{made.how}. It won't be shown again. To change it, make a new one; this one expires by itself.</div>}
      </Card>
      <div><Btn kind="ghost" onClick={() => setMade(null)}>Back to codes</Btn></div>
    </Page>
  )
  return (
    <Page>
      <Title sub={`An invitation opens exactly what it says, on ${me}. It is shown once, used once, and always expires.`}>Codes and invitations</Title>
      <div style={{ display: 'grid', gridTemplateColumns: narrow ? '1fr' : 'repeat(4, minmax(0, 1fr))', gap: 12 }}>
        {TEMPLATES.filter((t) => owner || t.f.kind !== 'device').map((t) => (
          <button key={t.id} type="button" onClick={() => setF({ ...t.f, tmpl: t.t })} className="tl-focus" style={{ textAlign: 'left', border: '1.5px solid ' + (f.tmpl === t.t ? T.ink : T.rule), background: T.surf, borderRadius: 10, padding: 16, cursor: 'pointer', color: T.ink, display: 'grid', gap: 6, alignContent: 'start', font: 'inherit' }}>
            <b style={{ fontSize: 15 }}>{t.t}</b><span style={{ fontSize: 13, color: T.sub, lineHeight: 1.45 }}>{t.d}</span>
          </button>
        ))}
      </div>
      <Card>
        <Section>{f.tmpl ? 'Template: ' + f.tmpl + ' · everything is editable' : 'From scratch'}</Section>
        <div style={{ display: 'grid', gap: 16, marginTop: 8 }}>
          <div style={{ display: 'grid', gap: 6 }}><span style={{ fontSize: 13.5, fontWeight: 600 }}>Who it is for</span><Seg label="Who it is for" value={f.kind} onChange={(v) => set({ kind: v, tmpl: null })} options={kinds} /></div>
          <label style={{ display: 'grid', gap: 6, fontSize: 13.5, fontWeight: 600 }}>Name<input className="tl-input" value={f.name} onChange={(e) => set({ name: e.target.value.toLowerCase().replace(/[^a-z0-9._-]/g, '') })} style={{ minHeight: 44, borderRadius: 7, border: '1.5px solid ' + T.ink, background: T.surf, color: T.ink, padding: '0 10px', font: '14px ' + FONT_SANS, maxWidth: 320 }} /></label>
          {f.kind !== 'runner' && <div style={{ display: 'grid', gap: 6 }}><span style={{ fontSize: 13.5, fontWeight: 600 }}>What they can use on {me}</span><div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>{GRANTABLE.map((c) => <Check key={c} on={f.allow.includes(c)} onClick={() => toggleCap(c)} label={capWord(c)} />)}</div>{f.allow.includes('shell') && <span style={{ fontSize: 12.5, color: T.bad }}>A shell lets them do anything you can on {me}.</span>}</div>}
          <div style={{ display: 'grid', gap: 6 }}><span style={{ fontSize: 13.5, fontWeight: 600 }}>Ends</span><Seg label="Ends" value={f.expires} onChange={(v) => set({ expires: v })} options={ENDS} /></div>
          <div style={{ display: 'grid', gap: 6 }}><Section>The most it can grow into</Section><div style={{ fontSize: 15, fontWeight: 500 }}>{ceiling}</div></div>
          <div style={{ display: 'grid', gap: 6 }}><Section>They will see</Section><Line>{preview}</Line></div>
          {err && <div role="alert" style={{ color: T.bad, fontSize: 14, whiteSpace: 'pre-line' }}>{err}</div>}
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            <Btn kind="pri" testid="make-invite" disabled={!f.name || A.busy} onClick={make}>Make the invitation</Btn>
            <span style={{ fontSize: 13, color: T.sub, flex: 1, minWidth: 220 }}>{me} is the device it opens, so {me} makes it. To read a code out loud instead, use the card below.</span>
          </div>
        </div>
      </Card>
      <SpokenCode A={A} />
      <Card><Section>Open invitations</Section><div style={{ fontSize: 14, color: T.sub, padding: '8px 0' }}>Invitations are not listed yet. Each one works once and expires by itself.</div></Card>
    </Page>
  )
}

function QR({ qr, size = 168 }) {
  const { T } = useT()
  if (!qr || !qr.width) return null
  const w = qr.width, q = 2, n = w + 2 * q
  const rects = []
  for (let i = 0; i < w * w; i++) if (qr.cells[i] === '1') rects.push(<rect key={i} x={(i % w) + q} y={Math.floor(i / w) + q} width="1" height="1" />)
  return (
    <svg role="img" aria-label="QR code of the pairing code" width={size} height={size} viewBox={`0 0 ${n} ${n}`} shapeRendering="crispEdges" style={{ background: '#ffffff', borderRadius: 6, flexShrink: 0 }}>
      <g fill="#000000">{rects}</g>
    </svg>
  )
}

function SpokenCode({ A }) {
  const { T, narrow } = useT()
  const me = A.state.me.name
  const owner = A.state.me.owner
  const [kind, setKind] = React.useState('person')
  const [name, setName] = React.useState('')
  const [job, setJob] = React.useState(null)
  const [err, setErr] = React.useState(null)
  React.useEffect(() => { codeStatus().then((j) => { if (j && j.code) setJob(j) }) }, [])
  React.useEffect(() => {
    if (!job || (job.done && !job.active)) return
    const id = setInterval(async () => {
      const j = await codeStatus()
      if (j && j.ok) { setJob(j); if (j.done) A.refresh() }
    }, 1500)
    return () => clearInterval(id)
  }, [job && job.code, job && job.done])
  const show = async () => {
    setErr(null)
    const r = await startCode({ kind, name })
    if (r.ok) setJob({ active: true, code: r.code, name: r.name, qr: r.qr, kind })
    else setErr(r.error || r.message || 'That did not work.')
  }
  if (job && job.code) {
    const done = job.done
    return (
      <Card testid="spoken-code">
        <Section>Code for {job.name}</Section>
        <div style={{ display: 'flex', gap: 20, alignItems: 'center', flexWrap: 'wrap', marginTop: 8 }}>
          {!done && <QR qr={job.qr} />}
          <div style={{ display: 'grid', gap: 10, minWidth: 220, flex: 1 }}>
            {!done && <div data-testid="code" style={{ font: `600 ${narrow ? 20 : 26}px ${FONT_MONO}`, letterSpacing: '.02em', overflowWrap: 'anywhere' }}>{job.code}</div>}
            {!done && <div style={{ fontSize: 13.5, color: T.sub, lineHeight: 1.5 }}>Read it out or let them scan it. On their side: <code>tunlion join {job.code}</code>, or in a browser at tunlion.autumated.com choose "Remember a device" and type it. One claim, expires in 10 minutes.</div>}
            {!done && <span style={{ display: 'inline-flex', gap: 8, alignItems: 'center', fontSize: 14 }}><Mark size={16} anim="pulse" />Waiting for them to type it</span>}
            {done && (done.ok
              ? <><Applied>{job.name} is in</Applied><span style={{ fontSize: 14, color: T.sub }}>Paired with {me}. It now appears under Devices and people.</span></>
              : <div role="alert" style={{ fontSize: 14, color: T.bad, whiteSpace: 'pre-line' }}>{done.message || 'The code was not used.'}</div>)}
            <div style={{ display: 'flex', gap: 10 }}>
              {!done ? <Btn kind="ghost" onClick={async () => setJob(await cancelCode())}>Cancel this code</Btn> : <Btn onClick={() => setJob(null)}>Another code</Btn>}
            </div>
          </div>
        </div>
      </Card>
    )
  }
  return (
    <Card>
      <Section>Read out a code now · you are both here</Section>
      <div style={{ display: 'grid', gap: 14, marginTop: 8 }}>
        <div style={{ display: 'grid', gap: 6 }}><span style={{ fontSize: 13.5, fontWeight: 600 }}>Who it is for</span><Seg label="Who the code is for" value={kind} onChange={setKind} options={[['person', 'A person'], ...(owner ? [['device', 'One of my devices']] : [])]} /></div>
        <label style={{ display: 'grid', gap: 6, fontSize: 13.5, fontWeight: 600 }}>Name<input className="tl-input" value={name} onChange={(e) => setName(e.target.value.toLowerCase().replace(/[^a-z0-9._-]/g, ''))} placeholder={kind === 'device' ? 'phone' : 'dana'} style={{ minHeight: 44, borderRadius: 7, border: '1.5px solid ' + T.ink, background: T.surf, color: T.ink, padding: '0 10px', font: '14px ' + FONT_SANS, maxWidth: 320 }} /></label>
        <div style={{ fontSize: 14 }}>{kind === 'device' ? `It joins your devices with files and folders, as tunlion add --for device does. Shell stays off.` : `You remember each other. They can send files to ${me}; nothing else until you allow it.`}</div>
        {err && <div role="alert" style={{ color: T.bad, fontSize: 14, whiteSpace: 'pre-line' }}>{err}</div>}
        <div><Btn kind="pri" testid="show-code" disabled={!name || A.busy} onClick={show}>Show a code</Btn></div>
      </div>
    </Card>
  )
}

function Asks({ A }) {
  const { T } = useT()
  return (
    <Page>
      <Title sub={`Requests that wait on ${A.state.me.name}, newest first. Each names the exact access.`}>Asks</Title>
      <Card><Section>Waiting on you · {A.asks.length}</Section>{!A.asks.length && <div style={{ fontSize: 14, color: T.sub, padding: '10px 0' }}>{A.state.daemon.answering ? 'Nothing waiting on you.' : 'The background service is not answering, so asks cannot be read.'}</div>}{A.asks.map((a) => <AskCard key={a.id} a={a} A={A} />)}</Card>
    </Page>
  )
}

function Exposure({ A }) {
  const { T, narrow } = useT()
  const tone = { high: 'bad', mid: 'acc', low: 'n' }
  const fix = (x) => {
    if (x.open) return A.open(x.open)
    const msg = x.act.verb === 'cut' ? `${x.name} cut off.` : `${x.name} can no longer open a shell on ${A.state.me.name}.`
    A.run(x.act.verb, x.act, msg)
  }
  return (
    <Page>
      <Title sub={`What can reach ${A.state.me.name}, riskiest first. Each item has one fix, or mark it as fine.`}>Exposure</Title>
      {A.state.me.owner && <div style={{ fontSize: 13.5, color: T.sub }}>{A.state.me.name} holds your owner key: anyone with this machine can add devices to yours. Keep it on one device.</div>}
      {!A.ex.length ? <Card><Applied>Nothing else needs a look.</Applied><p style={{ fontSize: 14.5, margin: '10px 0 0', color: T.sub }}>Run it again after you add devices or make invitations.</p></Card> : (
        <Card>
          <Section>{A.ex.length} to look at</Section>
          {A.ex.map((x, i) => (
            <div key={x.id} data-testid="exposure-item" data-risk={x.risk} style={{ display: 'flex', gap: 14, alignItems: 'flex-start', padding: '14px 0', borderBottom: '1px solid ' + T.rule, flexWrap: narrow ? 'wrap' : 'nowrap' }}>
              {!narrow && <span style={{ font: '600 12px ' + FONT_MONO, color: T.sub, width: 22, paddingTop: 3 }}>{i + 1}</span>}
              <div style={{ flex: narrow ? '1 1 100%' : 1, minWidth: 0, display: 'grid', gap: 5 }}>
                <div style={{ fontSize: 15, lineHeight: 1.4 }}><b>{x.title}</b>{' '}<Tag tone={tone[x.risk]}>{x.risk === 'high' ? 'high' : x.risk === 'mid' ? 'medium' : 'check'}</Tag></div>
                <span style={{ font: '500 12.5px/1.45 ' + FONT_MONO, color: T.sub, overflowWrap: 'anywhere' }}>{x.sub}</span>
              </div>
              <span style={{ display: 'flex', gap: 8, flexShrink: 0 }}><Btn small kind={x.risk === 'high' ? 'pri' : 'sec'} onClick={() => fix(x)}>{x.fix}</Btn><Btn small kind="ghost" onClick={() => A.setDone((d) => [...d, x.id])}>Looks fine</Btn></span>
            </div>
          ))}
        </Card>
      )}
    </Page>
  )
}

function History({ A }) {
  const { T } = useT()
  const [kind, setKind] = React.useState('all')
  const [q, setQ] = React.useState('')
  const all = toHistory(A.state)
  const list = all.filter((h) => (kind === 'all' || h.kind === kind) && (!q || h.text.toLowerCase().includes(q.toLowerCase())))
  return (
    <Page>
      <Title sub={`From ${A.state.me.name}'s own log, newest first. Other devices keep their own.`}>History</Title>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
        <input className="tl-input" aria-label="Search the log" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search the log" style={{ minHeight: 44, border: '1.5px solid ' + T.ink, borderRadius: 8, padding: '0 14px', font: '15px ' + FONT_SANS, background: T.surf, color: T.ink, minWidth: 220 }} />
        <div style={{ minWidth: 320 }}><Seg label="Kind" value={kind} onChange={setKind} options={[['all', 'All'], ['shell', 'Shell'], ['files', 'Files'], ['access', 'Access']]} /></div>
      </div>
      <Card>
        {!list.length && <div style={{ fontSize: 14, color: T.sub, padding: '10px 0' }}>Nothing matches.</div>}
        {list.slice(0, 200).map((h, i) => <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid ' + T.rule, font: '500 12.5px/1.45 ' + FONT_MONO, color: T.ink, overflowWrap: 'anywhere' }}>{h.text}</div>)}
      </Card>
    </Page>
  )
}
