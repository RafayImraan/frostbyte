"use client";

import { useEffect, useState } from "react";

export function ThemeToggle() {
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  useEffect(() => {
    const stored = localStorage.getItem("cybershield-theme");
    const initial = stored === "light" ? "light" : "dark";
    setTheme(initial);
    document.documentElement.classList.toggle("theme-light", initial === "light");
  }, []);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    localStorage.setItem("cybershield-theme", next);
    document.documentElement.classList.toggle("theme-light", next === "light");
  };

  return (
    <button
      className="fixed bottom-6 right-6 z-50 px-4 py-2 rounded-full bg-carbon/80 border border-slate-700 text-xs text-slate-200 hover:text-white"
      onClick={toggleTheme}
    >
      Theme: {theme === "dark" ? "Dark" : "Light"}
    </button>
  );
}
