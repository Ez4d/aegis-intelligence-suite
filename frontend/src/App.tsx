import { FormEvent, ReactNode, useEffect, useMemo, useState } from "react";
import { CircleAlert, Crosshair, Fingerprint, Globe2, KeyRound, LockKeyhole, MapPin, Radar, Search, ShieldCheck, UploadCloud } from "lucide-react";
import L from "leaflet";
import { MapContainer, Marker, TileLayer, useMap } from "react-leaflet";

const API = import.meta.env.VITE_API_URL ?? "";
type Coordinates = { latitude: number; longitude: number };
type AuthState = { token: string; username: string };
type ExifResult = { filename: string; format: string | null; metadata: Record<string, unknown>; gps: Coordinates | null };
type NetworkLookupResult = {
  hostname: string;
  addresses: string[];
  reverse_hostname: string | null;
  location: { city: string | null; region: string | null; country: string | null; latitude: number; longitude: number };
};
type Profile = { platform: string; handle: string; url: string };

const reticleIcon = L.divIcon({
  className: "reticle-wrap",
  html: '<span class="reticle"><i></i></span>',
  iconSize: [38, 38],
  iconAnchor: [19, 19],
});

function MapFocus({ coordinates }: { coordinates: Coordinates | null }) {
  const map = useMap();
  useEffect(() => {
    if (coordinates) map.flyTo([coordinates.latitude, coordinates.longitude], 14, { duration: 1 });
  }, [coordinates, map]);
  return coordinates ? <Marker position={[coordinates.latitude, coordinates.longitude]} icon={reticleIcon} /> : null;
}

async function api<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(init.headers);
  if (!(init.body instanceof FormData)) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let response: Response;
  try {
    response = await fetch(`${API}${path}`, { ...init, headers });
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error("Cannot reach the backend API. Start the backend in the backend folder, then try again.");
    }
    throw error;
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail ?? `Request failed (${response.status}).`);
  }
  return response.json() as Promise<T>;
}

export default function App() {
  const [auth, setAuth] = useState<AuthState | null>(() => {
    try {
      const saved = sessionStorage.getItem("aegis-auth");
      return saved ? JSON.parse(saved) as AuthState : null;
    } catch {
      sessionStorage.removeItem("aegis-auth");
      return null;
    }
  });
  const [coordinates, setCoordinates] = useState<Coordinates | null>(null);
  const [exif, setExif] = useState<ExifResult | null>(null);
  const [busyExif, setBusyExif] = useState(false);
  const [exifError, setExifError] = useState("");
  const [password, setPassword] = useState("");
  const [passwordResult, setPasswordResult] = useState<{ compromised: boolean; frequency: number } | null>(null);
  const [passwordError, setPasswordError] = useState("");
  const [busyPassword, setBusyPassword] = useState(false);
  const [networkQuery, setNetworkQuery] = useState("");
  const [networkResult, setNetworkResult] = useState<NetworkLookupResult | null>(null);
  const [networkError, setNetworkError] = useState("");
  const [busyNetwork, setBusyNetwork] = useState(false);
  const [networkAuthorized, setNetworkAuthorized] = useState(false);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profilePlatform, setProfilePlatform] = useState("GitHub");
  const [profileHandle, setProfileHandle] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [profileNotice, setProfileNotice] = useState("");

  const metadataRows = useMemo(() => exif ? Object.entries(exif.metadata).slice(0, 12) : [], [exif]);

  async function inspectImage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setExifError("");
    setExif(null);
    setCoordinates(null);
    const data = new FormData(event.currentTarget);
    if (!data.get("image")) return;
    setBusyExif(true);
    try {
      const result = await api<ExifResult>("/api/exif", { method: "POST", body: data }, auth?.token);
      setExif(result);
      if (result.gps) setCoordinates(result.gps);
    } catch (error) {
      setExifError(error instanceof Error ? error.message : "Image inspection failed.");
    } finally {
      setBusyExif(false);
    }
  }

  async function checkPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPasswordError("");
    setPasswordResult(null);
    setBusyPassword(true);
    try {
      const result = await api<{ compromised: boolean; frequency: number }>("/api/password-check", {
        method: "POST",
        body: JSON.stringify({ password }),
      });
      setPasswordResult(result);
    } catch (error) {
      setPasswordError(error instanceof Error ? error.message : "Password check failed.");
    } finally {
      setPassword("");
      setBusyPassword(false);
    }
  }

  async function lookupNetwork(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setNetworkError("");
    setNetworkResult(null);
    setBusyNetwork(true);
    try {
      const result = await api<NetworkLookupResult>("/api/network-lookup", {
        method: "POST",
        body: JSON.stringify({ query: networkQuery, authorized: networkAuthorized }),
      }, auth?.token);
      setNetworkResult(result);
      setCoordinates({ latitude: result.location.latitude, longitude: result.location.longitude });
    } catch (error) {
      setNetworkError(error instanceof Error ? error.message : "Network lookup failed.");
    } finally {
      setBusyNetwork(false);
    }
  }

  function addProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setProfileNotice("");
    const handle = profileHandle.trim().replace(/^@/, "");
    if (!authorized) {
      setProfileNotice("Confirm that you own or are authorized to manage this profile.");
      return;
    }
    if (!/^[a-zA-Z0-9._-]{1,64}$/.test(handle)) {
      setProfileNotice("Enter a valid handle using letters, numbers, dots, underscores, or hyphens.");
      return;
    }
    const hosts: Record<string, string> = {
      GitHub: "github.com", Instagram: "instagram.com", LinkedIn: "linkedin.com/in", X: "x.com",
    };
    const profile = { platform: profilePlatform, handle, url: `https://${hosts[profilePlatform]}/${encodeURIComponent(handle)}` };
    setProfiles((items) => [profile, ...items.filter((item) => item.platform !== profile.platform || item.handle !== handle)]);
    setProfileHandle("");
    setProfileNotice("Added to this browser's local inventory. No profile was fetched.");
  }

  function saveAuth(value: AuthState) {
    sessionStorage.setItem("aegis-auth", JSON.stringify(value));
    setAuth(value);
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="#"><span className="brand-mark"><ShieldCheck size={21} /></span><span>AEGIS<span className="brand-light"> / INTELLIGENCE SUITE</span></span></a>
        <div className="top-status"><span className="status-dot" /> PRIVACY OPERATIONS <span className="divider">|</span> {auth ? auth.username : "SESSION LOCKED"}</div>
      </header>
      <section className="hero">
        <div>
          <div className="eyebrow"><Radar size={14} /> PERSONAL SECURITY CONSOLE</div>
          <h1>Privacy, in <span>clear view.</span></h1>
          <p>Inspect image metadata, check password exposure safely, and organize profiles you are authorized to manage.</p>
        </div>
        <AuthPanel auth={auth} onAuth={saveAuth} onLogout={() => { sessionStorage.removeItem("aegis-auth"); setAuth(null); }} />
      </section>

      <section className="dashboard-grid">
        <article className="panel map-panel">
          <PanelTitle icon={<MapPin size={17} />} eyebrow="LOCATION INTELLIGENCE" title="EXIF coordinate viewer" tag="LIVE MAP" />
          <div className="map-frame">
            <MapContainer center={[20, 0]} zoom={2} scrollWheelZoom className="leaflet-map">
              <TileLayer
                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
              />
              <MapFocus coordinates={coordinates} />
            </MapContainer>
            {!coordinates && <div className="map-empty"><Crosshair size={25} /><span>Awaiting image coordinates</span><small>Upload an image containing GPS EXIF data</small></div>}
          </div>
          <div className="map-footer">
            <div><span className="muted-label">TARGET COORDINATES</span><strong>{coordinates ? `${coordinates.latitude.toFixed(6)}, ${coordinates.longitude.toFixed(6)}` : "NO FIX"}</strong></div>
            <span className={`pill ${coordinates ? "pill-cyan" : ""}`}>{coordinates ? "MARKER ACTIVE" : "STANDBY"}</span>
          </div>
        </article>

        <article className="panel">
          <PanelTitle icon={<Globe2 size={17} />} eyebrow="PUBLIC NETWORK LOOKUP" title="URL / IP locator" tag="DNS + GEO" />
          <p className="panel-copy">Resolve a public website to its IP addresses, or look up reverse DNS and approximate location for a public IP. Use only domains and addresses you are authorized to inspect.</p>
          <form className="stack-form" onSubmit={lookupNetwork}>
            <label className="field-label" htmlFor="network-query">WEBSITE URL, DOMAIN, OR PUBLIC IP</label>
            <input id="network-query" className="text-input" value={networkQuery} onChange={(event) => setNetworkQuery(event.target.value)} maxLength={2048} placeholder="https://example.com or 8.8.8.8" required />
            <label className="consent-check"><input type="checkbox" checked={networkAuthorized} onChange={(event) => setNetworkAuthorized(event.target.checked)} /> I own or am authorized to look up this domain or IP.</label>
            <button className="button button-primary" disabled={busyNetwork || !auth || !networkAuthorized}>{busyNetwork ? "LOOKING UP..." : <><Search size={13} /> LOOK UP IP / LOCATION</>}</button>
          </form>
          {!auth && <p className="inline-hint">Sign in to use network lookup.</p>}
          {networkError && <p className="error-line"><CircleAlert size={15} />{networkError}</p>}
          {networkResult && <div className="results">
            <div className="result-heading"><strong>{networkResult.hostname}</strong><span>PUBLIC DNS</span></div>
            <dl className="metadata-list">
              <div><dt>IP addresses</dt><dd>{networkResult.addresses.join(", ")}</dd></div>
              <div><dt>Reverse DNS</dt><dd>{networkResult.reverse_hostname ?? "No reverse DNS record"}</dd></div>
              <div><dt>Approx. location</dt><dd>{[networkResult.location.city, networkResult.location.region, networkResult.location.country].filter(Boolean).join(", ") || "Not provided"}</dd></div>
              <div><dt>Coordinates</dt><dd>{networkResult.location.latitude.toFixed(5)}, {networkResult.location.longitude.toFixed(5)}</dd></div>
            </dl>
            <p className="inline-hint">Approximate IP location is provided by ipapi.co; the selected public IP is shared with that service. The map marker shows this approximate location.</p>
          </div>}
        </article>

        <article className="panel">
          <PanelTitle icon={<Fingerprint size={17} />} eyebrow="METADATA FORENSICS" title="Image inspector" tag="EXIF" />
          <p className="panel-copy">Extract camera details and embedded location from your image. Uploads are processed in memory and are not stored.</p>
          <form className="upload-form" onSubmit={inspectImage}>
            <label className="file-drop">
              <UploadCloud size={23} />
              <span>Choose an image to inspect</span>
              <small>JPEG, TIFF, or WebP · max 12 MiB</small>
              <input name="image" type="file" accept="image/jpeg,image/tiff,image/webp" required />
            </label>
            <button className="button button-primary" disabled={busyExif || !auth}>{busyExif ? "INSPECTING..." : "INSPECT IMAGE"}</button>
          </form>
          {!auth && <p className="inline-hint">Sign in to inspect image metadata.</p>}
          {exifError && <p className="error-line"><CircleAlert size={15} />{exifError}</p>}
          {exif && <div className="results">
            <div className="result-heading"><strong>{exif.filename}</strong><span>{exif.format ?? "IMAGE"}</span></div>
            {exif.gps ? <div className="success-line"><MapPin size={15} /> GPS coordinates found and plotted on the map.</div> : <div className="inline-hint">No GPS coordinates found in this image.</div>}
            {metadataRows.length > 0 && <dl className="metadata-list">{metadataRows.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{String(value)}</dd></div>)}</dl>}
          </div>}
        </article>

        <article className="panel">
          <PanelTitle icon={<KeyRound size={17} />} eyebrow="CREDENTIAL EXPOSURE" title="Password safety check" tag="K-ANONYMITY" />
          <p className="panel-copy">Checks the HIBP corpus using a SHA-1 prefix query. Your password is never sent; only the first five hash characters are transmitted.</p>
          <form className="stack-form" onSubmit={checkPassword}>
            <label className="field-label" htmlFor="check-password">PASSWORD TO CHECK</label>
            <input id="check-password" className="text-input" type="password" autoComplete="new-password" minLength={1} maxLength={256} value={password} onChange={(event) => setPassword(event.target.value)} required />
            <button className="button button-primary" disabled={busyPassword}>{busyPassword ? "CHECKING..." : "CHECK EXPOSURE"}</button>
          </form>
          {passwordError && <p className="error-line"><CircleAlert size={15} />{passwordError}</p>}
          {passwordResult && <div className={`risk-result ${passwordResult.compromised ? "risk-high" : "risk-low"}`}>
            {passwordResult.compromised ? <CircleAlert size={20} /> : <ShieldCheck size={20} />}
            <div><strong>{passwordResult.compromised ? "EXPOSED PASSWORD" : "NO MATCH FOUND"}</strong><span>{passwordResult.compromised ? `Seen ${passwordResult.frequency.toLocaleString()} times in known breaches. Change it anywhere you use it.` : "No match found in the queried breach corpus."}</span></div>
          </div>}
          <div className="privacy-note"><LockKeyhole size={14} /> Password value is cleared after every check.</div>
        </article>

        <article className="panel profile-panel">
          <PanelTitle icon={<Radar size={17} />} eyebrow="AUTHORIZED ACCOUNT INVENTORY" title="Profile organizer" tag="LOCAL ONLY" />
          <p className="panel-copy">Keep links to accounts you own or are authorized to manage. This tool does not scrape, contact, or collect data from social platforms.</p>
          <form className="stack-form" onSubmit={addProfile}>
            <label className="field-label" htmlFor="platform">PLATFORM</label>
            <select id="platform" className="text-input" value={profilePlatform} onChange={(event) => setProfilePlatform(event.target.value)}>
              <option>GitHub</option><option>Instagram</option><option>LinkedIn</option><option>X</option>
            </select>
            <label className="field-label" htmlFor="handle">YOUR AUTHORIZED HANDLE</label>
            <input id="handle" className="text-input" value={profileHandle} onChange={(event) => setProfileHandle(event.target.value)} maxLength={64} placeholder="account-name" required />
            <label className="consent-check"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /> I own this account or have permission to manage it.</label>
            <button className="button button-secondary" type="submit">ADD TO LOCAL INVENTORY</button>
          </form>
          {profileNotice && <p className="inline-hint">{profileNotice}</p>}
          {profiles.length > 0 && <ul className="profile-list">{profiles.map((profile) => <li key={`${profile.platform}:${profile.handle}`}><span><strong>{profile.platform}</strong><small>{profile.handle}</small></span><a href={profile.url} target="_blank" rel="noreferrer">OPEN ↗</a><button aria-label={`Remove ${profile.handle}`} onClick={() => setProfiles((items) => items.filter((item) => item !== profile))}>×</button></li>)}</ul>}
        </article>
      </section>
      <footer className="footer"><span>AEGIS INTELLIGENCE SUITE</span><span>Use only with data and accounts you are authorized to inspect.</span></footer>
    </main>
  );
}

function PanelTitle({ icon, eyebrow, title, tag }: { icon: ReactNode; eyebrow: string; title: string; tag: string }) {
  return <div className="panel-title"><div className="panel-icon">{icon}</div><div className="panel-heading"><span>{eyebrow}</span><h2>{title}</h2></div><span className="panel-tag">{tag}</span></div>;
}

function AuthPanel({ auth, onAuth, onLogout }: { auth: AuthState | null; onAuth: (value: AuthState) => void; onLogout: () => void }) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      const result = await api<{ username: string; access_token: string }>("/api/auth/" + mode, {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      onAuth({ username: result.username, token: result.access_token });
      setPassword("");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Authentication failed.");
    } finally {
      setBusy(false);
    }
  }
  if (auth) return <div className="auth-card auth-logged-in"><div className="auth-icon"><ShieldCheck size={18} /></div><div className="auth-info"><span>SESSION AUTHENTICATED</span><strong>{auth.username}</strong></div><button className="text-button" onClick={onLogout}>SIGN OUT</button></div>;
  return <form className="auth-card" onSubmit={submit}>
    <div className="auth-card-head"><div className="auth-icon"><LockKeyhole size={17} /></div><div><span>{mode === "login" ? "SECURE ACCESS" : "CREATE ACCOUNT"}</span><strong>{mode === "login" ? "Sign in to Aegis" : "Register an account"}</strong></div></div>
    <input className="auth-input" aria-label="Username" autoComplete="username" minLength={3} maxLength={32} placeholder="Username" value={username} onChange={(event) => setUsername(event.target.value)} required />
    <input className="auth-input" aria-label="Password" type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} minLength={12} maxLength={128} placeholder="Password (12+ characters)" value={password} onChange={(event) => setPassword(event.target.value)} required />
    {error && <span className="auth-error">{error}</span>}
    <div className="auth-actions"><button className="button button-primary" disabled={busy}>{busy ? "PLEASE WAIT..." : mode === "login" ? "SIGN IN" : "REGISTER"}</button><button type="button" className="text-button" onClick={() => { setMode(mode === "login" ? "register" : "login"); setError(""); }}>{mode === "login" ? "CREATE ACCOUNT" : "SIGN IN"}</button></div>
  </form>;
}
