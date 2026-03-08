import { useState } from "react";
import type { Playbook as PlaybookType } from "@/lib/playbookData";
import PlaybookSelector from "@/components/PlaybookSelector";
import PlaybookViewer from "@/components/PlaybookViewer";
import { Shield, BookOpen } from "lucide-react";
import { NavLink } from "@/components/NavLink";

const Playbook = () => {
  const [selectedPlaybook, setSelectedPlaybook] = useState<PlaybookType | null>(null);

  return (
    <div className="min-h-screen bg-background scanline">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <header className="border-b border-border px-6 py-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <BookOpen className="h-8 w-8 text-primary" />
              </div>
              <div>
                <h1 className="text-xl font-bold tracking-tight text-foreground font-mono">
                  IR <span className="text-primary">PLAYBOOK</span> ENGINE
                </h1>
                <p className="text-xs text-muted-foreground">
                  Open-source incident response playbook generator
                </p>
              </div>
            </div>
            <nav className="flex items-center gap-1">
              <NavLink to="/" className="px-3 py-1.5 text-xs font-mono text-muted-foreground hover:text-foreground transition-colors rounded-md hover:bg-secondary">
                <span className="flex items-center gap-1.5"><Shield className="h-3.5 w-3.5" /> THREATS</span>
              </NavLink>
              <NavLink to="/alerts" className="px-3 py-1.5 text-xs font-mono text-muted-foreground hover:text-foreground transition-colors rounded-md hover:bg-secondary">
                <span className="flex items-center gap-1.5"><Shield className="h-3.5 w-3.5" /> XDR ALERTS</span>
              </NavLink>
              <span className="px-3 py-1.5 text-xs font-mono text-primary bg-primary/10 rounded-md border border-primary/20">
                <span className="flex items-center gap-1.5"><BookOpen className="h-3.5 w-3.5" /> PLAYBOOKS</span>
              </span>
            </nav>
          </div>
        </header>

        {selectedPlaybook ? (
          <PlaybookViewer playbook={selectedPlaybook} onBack={() => setSelectedPlaybook(null)} />
        ) : (
          <PlaybookSelector onSelect={setSelectedPlaybook} />
        )}
      </div>
    </div>
  );
};

export default Playbook;
