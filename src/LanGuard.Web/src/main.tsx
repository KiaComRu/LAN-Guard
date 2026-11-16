import { StrictMode, useEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { api, ApiError, mutate } from './api';
import type { Detection, DetectionRow, Detail, Device, Overview, Page, Session } from './api';
import './styles.css';

type Tab = 'devices' | 'detections';
const auditLabels: Record<string, string> = { scanned: 'Проверен', partial_scan: 'Частичная проверка', not_scanned: 'Не проверен' };
const sourceLabels: Record<string, string> = {
  machineRegistry: 'Реестр компьютера', userRegistry: 'Реестр загруженных профилей',
  processes: 'Процессы', services: 'Службы', registry: 'Реестр', process: 'Процесс', service: 'Служба',
  autoruns: 'Run и RunOnce', scheduledTasks: 'Планировщик заданий', autorun: 'Автозапуск', task: 'Задание',
};
const eventLabels: Record<string, string> = {
  detected: 'Обнаружение', started: 'Замечен запуск', reappeared: 'Повторное обнаружение',
  no_longer_observed: 'Больше не наблюдается', partial_scan: 'Частичная проверка',
};
const fieldLabels: Record<string, string> = {
  name: 'имя', originalFilename: 'исходное имя файла', product: 'название продукта', publisher: 'издатель',
};
const dateFormatter = new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
const date = (value: string | null) => value ? dateFormatter.format(new Date(value)) : '—';
const message = (error: unknown) => error instanceof ApiError ? error.message : 'Нет связи с сервером.';

function App() {
  const [session, setSession] = useState<Session | null | undefined>();
  const [error, setError] = useState('');

  function readSession() {
    setError('');
    api<Session>('/auth/session').then(setSession).catch(error => {
      if (error instanceof ApiError && error.status === 401) setSession(null);
      else setError(message(error));
    });
  }
  useEffect(readSession, []);

  if (session === undefined) return <main className="centered">
    {error ? <><p role="alert">{error}</p><button onClick={readSession}>Повторить</button></> : <p>Загрузка…</p>}
  </main>;
  if (!session) return <Login onLogin={setSession} />;
  return <Dashboard session={session} onLogout={() => setSession(null)} />;
}

function Login({ onLogin }: { onLogin: (session: Session) => void }) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const values = new FormData(event.currentTarget);
    setBusy(true);
    setError('');
    try {
      await mutate('/auth/login', { login: values.get('login'), password: values.get('password') });
      onLogin(await api<Session>('/auth/session'));
    } catch (error) {
      setError(error instanceof ApiError && error.status === 401 ? 'Неверный логин или пароль.' : message(error));
    } finally {
      setBusy(false);
    }
  }

  return <main className="centered">
    <section className="login">
      <Brand />
      <h1>Вход в панель</h1>
      <form onSubmit={submit}>
        <label>Логин<input name="login" required maxLength={100} autoComplete="username" /></label>
        <label>Пароль<input name="password" type="password" required maxLength={256} autoComplete="current-password" /></label>
        {error && <p className="error" role="alert">{error}</p>}
        <button className="primary" disabled={busy}>{busy ? 'Вход…' : 'Войти'}</button>
      </form>
    </section>
  </main>;
}

function Brand() {
  return <div className="brand"><span className="mark" aria-hidden="true">LG</span><span>LAN Guard</span></div>;
}

function Dashboard({ session, onLogout }: { session: Session; onLogout: () => void }) {
  const [tab, setTab] = useState<Tab>('devices');
  const [overview, setOverview] = useState<Overview>();
  const [devices, setDevices] = useState<Page<Device>>();
  const [detections, setDetections] = useState<Page<DetectionRow>>();
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  const [page, setPage] = useState(1);
  const [revision, refresh] = useState(0);
  const [error, setError] = useState('');
  const [deviceId, setDeviceId] = useState<string>();
  const [token, setToken] = useState<{ token: string; expiresAt: string }>();
  const [issuing, setIssuing] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    api<Overview>('/overview', { signal: controller.signal }).then(setOverview).catch(error => {
      if (!controller.signal.aborted) setError(message(error));
    });
    return () => controller.abort();
  }, [revision]);

  useEffect(() => {
    const controller = new AbortController();
    const options = { signal: controller.signal };
    const params = new URLSearchParams({ page: String(page) });
    setDevices(undefined);
    setDetections(undefined);
    const handleError = (error: unknown) => {
      if (!controller.signal.aborted) setError(message(error));
    };
    if (tab === 'devices') {
      if (query) params.set('q', query);
      if (status) params.set('status', status);
      api<Page<Device>>('/devices?' + params, options).then(setDevices).catch(handleError);
    } else {
      api<Page<DetectionRow>>('/detections?' + params, options).then(setDetections).catch(handleError);
    }
    return () => controller.abort();
  }, [tab, page, query, status, revision]);

  async function issueToken() {
    setIssuing(true);
    try {
      setToken(await mutate<{ token: string; expiresAt: string }>('/enrollment-tokens'));
      setError('');
    } catch (error) {
      setError(message(error));
    } finally {
      setIssuing(false);
    }
  }
  function changeTab(next: Tab) {
    setTab(next);
    setPage(1);
  }

  const result = tab === 'devices' ? devices : detections;
  const totalPages = Math.ceil((result?.total ?? 0) / 50);

  return <>
    <header className="topbar">
      <div className="layout header-content">
        <Brand />
        <div className="account"><span>{session.login}</span>
          <button onClick={() => mutate('/auth/logout').then(onLogout).catch(error => setError(message(error)))}>Выйти</button>
        </div>
      </div>
    </header>
    <main className="layout dashboard">
      {session.demo && <aside className="demo">Демонстрационный режим. Все устройства и обнаружения вымышлены.</aside>}
      <div className="section-heading">
        <h1>Обзор сети</h1>
        <div className="actions">
          <button onClick={() => { setError(''); refresh(value => value + 1); }}>Обновить</button>
          {!session.demo && session.role === 'administrator' && <button className="primary" disabled={issuing}
            onClick={issueToken}>Токен агента</button>}
        </div>
      </div>
      {overview && <section className="metrics" aria-label="Показатели">
        <Metric label="Компьютеры" value={overview.devices} />
        <Metric label="Агенты на связи" value={overview.online} />
        <Metric label="Требуют проверки" value={overview.unverified} />
        <Metric label="Обнаружения" value={overview.detections} />
        <Metric label="Запущены при проверке" value={overview.active} />
        <Metric label="События за 24 ч" value={overview.eventsToday} />
      </section>}
      {error && <p className="error" role="alert">{error}</p>}
      <section className="panel">
        <div className="toolbar">
          <nav className="nav" aria-label="Разделы">
            <button aria-current={tab === 'devices' ? 'page' : undefined} onClick={() => changeTab('devices')}>Компьютеры</button>
            <button aria-current={tab === 'detections' ? 'page' : undefined} onClick={() => changeTab('detections')}>Обнаружения</button>
          </nav>
          {tab === 'detections' && <a className="button" href="/api/v1/reports/detections.csv">Скачать CSV</a>}
        </div>
        {tab === 'devices' && <form className="filters" onSubmit={event => {
          event.preventDefault(); setQuery(search.trim()); setPage(1);
        }}>
          <input aria-label="Имя или IP компьютера" placeholder="Имя компьютера или IP" value={search} maxLength={100}
            onChange={event => setSearch(event.target.value)} />
          <select aria-label="Статус проверки" value={status} onChange={event => {
            setStatus(event.target.value); setPage(1);
          }}>
            <option value="">Все статусы проверки</option>
            {Object.entries(auditLabels).map(([key, label]) => <option value={key} key={key}>{label}</option>)}
          </select>
          <button>Найти</button>
        </form>}
        {!result && !error && <p className="empty" role="status">Загрузка…</p>}
        {result?.total === 0 && <p className="empty">{tab === 'devices' ? 'Компьютеры не найдены.' : 'Обнаружений пока нет.'}</p>}
        {devices && devices.total > 0 && <DeviceTable devices={devices.items} onSelect={setDeviceId} />}
        {detections && detections.total > 0 && <DetectionTable rows={detections.items} onSelect={setDeviceId} />}
        {totalPages > 1 && <div className="pagination">
          <button disabled={page === 1} onClick={() => setPage(page - 1)}>Назад</button>
          <span>Страница {page} из {totalPages}</span>
          <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}>Далее</button>
        </div>}
      </section>
    </main>
    {deviceId && <DeviceDialog id={deviceId} close={() => setDeviceId(undefined)} />}
    {token && <Modal title="Регистрация агента" close={() => setToken(undefined)}>
      <p>Одноразовый токен действует до {date(token.expiresAt)}.</p>
      <label>Токен<input className="token" readOnly value={token.token} onFocus={event => event.target.select()} /></label>
    </Modal>}
  </>;
}

function Metric({ label, value }: { label: string; value: number }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong></div>;
}

function DeviceTable({ devices, onSelect }: { devices: Device[]; onSelect: (id: string) => void }) {
  return <div className="scroll"><table>
    <thead><tr><th>Компьютер</th><th>IP</th><th>Статус проверки</th><th>Агент</th><th>Обнаружения</th><th>Последняя связь</th></tr></thead>
    <tbody>{devices.map(device => <tr key={device.id}>
      <td><button className="text-button" onClick={() => onSelect(device.id)}>{device.hostname || 'Имя неизвестно'}</button>
        <small>{device.os}</small></td>
      <td className="addresses">{device.addresses.join(', ') || '—'}</td>
      <td><span className={'badge ' + device.auditStatus}>{auditLabels[device.auditStatus] ?? 'Неизвестно'}</span></td>
      <td>{device.hasAgent ? (device.online ? 'На связи' : 'Нет связи') : 'Отсутствует'}</td>
      <td>{device.detections.map(item => item.productFamily).join(', ') ||
        (device.result === 'not_detected' ? 'Не обнаружено' : 'Неизвестно')}</td>
      <td>{date(device.lastHeartbeat)}</td>
    </tr>)}</tbody>
  </table></div>;
}

function DetectionTable({ rows, onSelect }: { rows: DetectionRow[]; onSelect: (id: string) => void }) {
  return <div className="scroll"><table>
    <thead><tr><th>Программа</th><th>Компьютер</th><th>Активность при проверке</th><th>Уверенность</th><th>Последнее обнаружение</th></tr></thead>
    <tbody>{rows.map(({ id, hostname, detection }) => <tr key={id + detection.familyId}>
      <td><strong>{detection.productFamily}</strong><small>{detection.category === 'windows' ? 'Компонент Windows' : 'Стороннее ПО'}</small></td>
      <td><button className="text-button" onClick={() => onSelect(id)}>{hostname || 'Имя неизвестно'}</button></td>
      <td>{activity(detection)}</td><td>{confidence(detection)}</td><td>{date(detection.lastSeen)}</td>
    </tr>)}</tbody>
  </table></div>;
}

function activity(detection: Detection) {
  return detection.currentlyRunning === true ? 'Запущено' : detection.currentlyRunning === false ? 'Не запущено' : 'Неизвестно';
}

function confidence(detection: Detection) {
  return detection.confidence === 'medium' ? 'Средняя' : 'Низкая';
}

function Modal({ title, close, children }: { title: string; close: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current!;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  return <dialog ref={ref} onCancel={event => { event.preventDefault(); close(); }} aria-label={title}>
    <header className="section-heading"><h2>{title}</h2><button onClick={close}>Закрыть</button></header>
    {children}
  </dialog>;
}

function DeviceDialog({ id, close }: { id: string; close: () => void }) {
  const [detail, setDetail] = useState<Detail>();
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    api<Detail>('/devices/' + id, { signal: controller.signal }).then(setDetail).catch(error => {
      if (!controller.signal.aborted) setError(message(error));
    });
    return () => controller.abort();
  }, [id]);
  return <Modal title={detail?.device.hostname || 'Карточка компьютера'} close={close}>
    {error && <p className="error" role="alert">{error}</p>}
    {!detail && !error && <p role="status">Загрузка…</p>}
    {detail && <>
      <dl className="device-info">
        <div><dt>ОС</dt><dd>{detail.device.os || 'Неизвестна'}</dd></div>
        <div><dt>Версия агента</dt><dd>{detail.agentVersion || '—'}</dd></div>
        <div><dt>Последняя проверка</dt><dd>{date(detail.device.lastScanAt)}</dd></div>
        <div><dt>Последняя связь</dt><dd>{date(detail.device.lastHeartbeat)}</dd></div>
      </dl>
      <h3>Покрытие проверки</h3>
      {detail.coverage.length ? <ul className="detail-list">{detail.coverage.map(item => <li key={item.source}>
        <strong>{sourceLabels[item.source] ?? item.source}</strong>
        <span>{item.status === 'complete' ? 'Проверен' : item.status === 'partial' ? 'Частично' : 'Недоступен'}
          {' · '}{item.entries} записей</span>
        {item.reason && <small>{item.reason}</small>}
      </li>)}</ul> : <p>Отчёт проверки отсутствует.</p>}
      <h3>Обнаружения</h3>
      {!detail.device.detections.length && <p>{detail.device.result === 'not_detected' ?
        'В проверенных источниках совпадений не найдено.' : 'Данных для вывода недостаточно.'}</p>}
      {detail.device.detections.map(item => <details key={item.familyId}>
        <summary>{item.productFamily}{item.version ? ' ' + item.version : ''} · {activity(item)} · уверенность {confidence(item).toLowerCase()}</summary>
        <ul className="detail-list">{item.evidence.map(({ observation, matchedFields }, index) => <li key={index}>
          <strong>{sourceLabels[observation.kind] ?? observation.kind} · {observation.name}</strong>
          <small>{matchedFields.map(field => fieldLabels[field] ?? field).join(', ')}</small>
          {observation.path && <code>{observation.path}</code>}
          {observation.publisher && <small>Издатель по метаданным · {observation.publisher}</small>}
        </li>)}</ul>
      </details>)}
      <h3>Последние события</h3>
      {detail.events.length ? <ul className="detail-list">{detail.events.map(event => <li key={event.id}>
        {eventLabels[event.type] ?? event.type}{event.familyId ? ' · ' + event.familyId : ''}<small>{date(event.occurredAt)}</small>
      </li>)}</ul> : <p>Событий пока нет.</p>}
    </>}
  </Modal>;
}

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
