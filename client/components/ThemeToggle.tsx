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
    <button className="theme-toggle" onClick={toggleTheme} aria-label="Toggle theme">
      <span className="theme-toggle-track" />
      <span className="theme-toggle-knob">{theme === "dark" ? "D" : "L"}</span>
      <span className="theme-toggle-label">{theme === "dark" ? "Dark Mode" : "Light Mode"}</span>
    </button>
  );
}
