import { createContext, useCallback, useContext, useState, type ReactNode } from "react";

export interface ToastMsg { id: number; title: string; body?: string; action?: { label: string; href: string }; bad?: boolean }
type Push = (t: Omit<ToastMsg, "id">) => void;
const Ctx = createContext<Push>(() => {});
export const useToast = () => useContext(Ctx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [list, setList] = useState<ToastMsg[]>([]);
  const push = useCallback<Push>((t) => {
    const id = Date.now() + Math.random();
    setList((l) => [...l, { ...t, id }]);
    setTimeout(() => setList((l) => l.filter((x) => x.id !== id)), t.bad ? 9000 : 6000);
  }, []);
  return (
    <Ctx.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {list.map((t) => (
          <div key={t.id} className={`toast${t.bad ? " bad" : ""}`}>
            <div className="t">{t.title}</div>
            {t.body && <div className="b">{t.body}</div>}
            {t.action && <a href={t.action.href}>{t.action.label}</a>}
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}
