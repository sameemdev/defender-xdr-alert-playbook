import { useEffect, useRef } from "react";
import { Input } from "@/components/ui/input";
import { Search, X, Command } from "lucide-react";

interface SearchBarProps {
  query: string;
  onChange: (query: string) => void;
}

const SearchBar = ({ query, onChange }: SearchBarProps) => {
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        inputRef.current?.focus();
      }
      if (e.key === "Escape" && document.activeElement === inputRef.current) {
        onChange("");
        inputRef.current?.blur();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onChange]);

  return (
    <div className="relative mb-5">
      <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
      <Input
        ref={inputRef}
        value={query}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Search alerts, MITRE techniques, KQL queries..."
        className="pl-10 pr-20 bg-card border-border font-mono text-sm h-11 focus:border-primary/50 focus:ring-1 focus:ring-primary/20 transition-all"
      />
      <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-2">
        {query ? (
          <button
            onClick={() => onChange("")}
            className="text-muted-foreground hover:text-foreground transition-colors p-0.5"
          >
            <X className="h-4 w-4" />
          </button>
        ) : (
          <kbd className="hidden sm:flex items-center gap-0.5 text-[10px] font-mono text-muted-foreground bg-secondary px-1.5 py-0.5 rounded border border-border">
            <Command className="h-2.5 w-2.5" />K
          </kbd>
        )}
      </div>
    </div>
  );
};

export default SearchBar;
