// Small parts for the dashboard, in the browser UI's tokens (ui/theme.js).
import React from 'react'
import { makeTheme, systemMode, FONT_SANS, FONT_MONO } from '../ui/theme.js'

export const Ctx = React.createContext(null)
export const useT = () => React.useContext(Ctx)
export { FONT_SANS, FONT_MONO }

export function useThemeMode() {
  const read = () => { try { return localStorage.getItem('tl-dash-theme') } catch (e) { return null } }
  const [picked, setPicked] = React.useState(read)
  const [sys, setSys] = React.useState(systemMode)
  React.useEffect(() => {
    let mq
    try { mq = window.matchMedia('(prefers-color-scheme: light)') } catch (e) { return }
    const f = () => setSys(systemMode())
    mq.addEventListener ? mq.addEventListener('change', f) : mq.addListener(f)
    return () => (mq.removeEventListener ? mq.removeEventListener('change', f) : mq.removeListener(f))
  }, [])
  const mode = picked || sys
  const toggle = () => {
    const next = mode === 'light' ? 'dark' : 'light'
    setPicked(next)
    try { localStorage.setItem('tl-dash-theme', next) } catch (e) { /* private window */ }
  }
  return [makeTheme(mode), toggle]
}

export function useNarrow() {
  const q = () => (typeof window !== 'undefined' ? window.innerWidth < 760 : false)
  const [n, setN] = React.useState(q)
  React.useEffect(() => { const f = () => setN(q()); window.addEventListener('resize', f); return () => window.removeEventListener('resize', f) }, [])
  return n
}

export function Mark({ size = 24, anim }) {
  const { T } = useT()
  const small = size < 24
  const cls = anim === 'knock' ? 'tl-knock' : anim === 'pulse' ? 'tl-pulse' : undefined
  return (
    <svg width={size} height={size} viewBox="0 0 80 80" style={{ display: 'block', flexShrink: 0 }} aria-hidden="true">
      {small
        ? <path d="M10 80 V26 Q10 8 28 8 H52 Q70 8 70 26 V80" fill="none" stroke={T.ink} strokeWidth="16" />
        : <path d="M12 74 V24 Q12 10 26 10 H54 Q68 10 68 24 V74" fill="none" stroke={T.ink} strokeWidth="10" />}
      {small
        ? <rect className={cls} x="31" y="42" width="18" height="38" fill={T.acc} />
        : <rect className={cls} x="33" y="46" width="14" height="28" fill={T.acc} />}
    </svg>
  )
}

export function Btn({ children, kind = 'sec', onClick, small, disabled, label, testid }) {
  const { T, narrow } = useT()
  const base = {
    font: '600 14px ' + FONT_SANS, minHeight: small && !narrow ? 36 : 44, padding: small ? '0 12px' : '0 18px',
    borderRadius: 7, cursor: disabled ? 'default' : 'pointer', display: 'inline-flex', alignItems: 'center',
    justifyContent: 'center', gap: 8, opacity: disabled ? 0.45 : 1, whiteSpace: 'nowrap',
  }
  const k = {
    pri: { background: T.ink, color: T.inv, border: '1.5px solid ' + T.ink },
    sec: { background: 'transparent', color: T.ink, border: '1.5px solid ' + T.ink },
    ghost: { background: 'transparent', color: T.sub, border: '1.5px solid transparent' },
    dan: { background: 'transparent', color: T.bad, border: '1.5px solid ' + T.bad },
  }[kind]
  return (
    <button type="button" onClick={disabled ? undefined : onClick} disabled={disabled} aria-label={label} data-testid={testid}
      className="tl-focus" style={{ ...base, ...k }}>{children}</button>
  )
}

export function Tag({ children, tone = 'n' }) {
  const { T } = useT()
  const c = { n: [T.soft, T.sub], ok: [T.okBg, T.ok], bad: [T.badBg, T.bad], acc: [T.soft, T.accInk] }[tone]
  return <span style={{ font: '600 10.5px/1 ' + FONT_MONO, letterSpacing: '.06em', textTransform: 'uppercase', padding: '5px 7px', borderRadius: 4, background: c[0], color: c[1], whiteSpace: 'nowrap' }}>{children}</span>
}

export function Section({ children, right }) {
  const { T } = useT()
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 12, marginBottom: 4 }}>
      <h2 style={{ margin: 0, font: '600 11px ' + FONT_MONO, letterSpacing: '.1em', textTransform: 'uppercase', color: T.sub }}>{children}</h2>
      {right}
    </div>
  )
}

export function Card({ children, pad, testid }) {
  const { T, narrow } = useT()
  return <div data-testid={testid} style={{ background: T.surf, border: '1px solid ' + T.rule, borderRadius: 10, padding: pad != null ? pad : narrow ? 14 : 20 }}>{children}</div>
}

export function Line({ children }) {
  const { T } = useT()
  return <div data-testid="plain-line" style={{ font: '500 12.5px/1.5 ' + FONT_MONO, color: T.ink, border: '1.5px solid ' + T.ink, borderRadius: 7, padding: '10px 12px', overflowWrap: 'anywhere' }}>{children}</div>
}

export function Row({ children }) {
  const { T } = useT()
  return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, padding: '12px 0', borderBottom: '1px solid ' + T.rule, minHeight: 48, flexWrap: 'wrap' }}>{children}</div>
}

export function Seg({ options, value, onChange, label }) {
  const { T, narrow } = useT()
  return (
    <div role="radiogroup" aria-label={label} style={{ display: 'flex', border: '1.5px solid ' + T.ink, borderRadius: 7, overflow: 'hidden', flexWrap: 'wrap' }}>
      {options.map(([v, l]) => (
        <button key={v} type="button" role="radio" aria-checked={value === v} onClick={() => onChange(v)} className="tl-focus"
          style={{ flex: 1, minWidth: 0, minHeight: narrow ? 44 : 40, padding: '0 12px', border: 0, borderRight: '1px solid ' + T.rule, background: value === v ? T.ink : 'transparent', color: value === v ? T.inv : T.ink, font: '600 13.5px ' + FONT_SANS, cursor: 'pointer', whiteSpace: 'nowrap' }}>{l}</button>
      ))}
    </div>
  )
}

export function Check({ on, onClick, label }) {
  const { T } = useT()
  return (
    <button type="button" role="checkbox" aria-checked={on} aria-label={label} onClick={onClick} className="tl-focus"
      style={{ display: 'inline-flex', alignItems: 'center', gap: 10, minHeight: 44, padding: '0 12px', borderRadius: 7, border: '1.5px solid ' + (on ? T.ink : T.rule), background: on ? T.soft : 'transparent', color: T.ink, font: '600 14px ' + FONT_SANS, cursor: 'pointer' }}>
      <span aria-hidden="true" style={{ width: 16, height: 16, borderRadius: 3, border: '1.5px solid ' + T.ink, background: on ? T.ink : 'transparent' }} />
      {label}
    </button>
  )
}

export function Applied({ children }) {
  const { T } = useT()
  return <span data-testid="applied" style={{ display: 'inline-flex', alignItems: 'center', gap: 8, font: '600 12px ' + FONT_MONO, color: T.ok }}><span style={{ width: 8, height: 8, borderRadius: 2, background: T.ok, flexShrink: 0 }} /><span>{children}</span></span>
}

export function Title({ children, sub, right }) {
  const { T, narrow } = useT()
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 16, flexWrap: 'wrap' }}>
      <div style={{ flex: 1, minWidth: 220, display: 'grid', gap: 6 }}>
        <h1 style={{ margin: 0, fontSize: narrow ? 24 : 28, letterSpacing: '-.015em', fontWeight: 600, color: T.ink }}>{children}</h1>
        {sub && <p style={{ margin: 0, fontSize: 14.5, lineHeight: 1.5, color: T.sub, maxWidth: '70ch' }}>{sub}</p>}
      </div>
      {right}
    </div>
  )
}

export function Page({ children }) {
  const { narrow } = useT()
  return <div style={{ padding: narrow ? '16px 16px 28px' : '30px 36px 40px', maxWidth: 1040, display: 'flex', flexDirection: 'column', gap: 20 }}>{children}</div>
}
