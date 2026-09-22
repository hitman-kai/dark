"use client";

import { useEffect, useState } from "react";

export default function RetroScrollbar() {
    const [progress, setProgress] = useState(0);

    // Increased from 35 to 85. This forces the flexbox to make each block 
    // shorter than it is wide, resulting in horizontal volume notches!
    const TOTAL_BLOCKS = 85;

    useEffect(() => {
        const handleScroll = () => {
            const scrollTop = window.scrollY || document.documentElement.scrollTop;
            const scrollHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;

            if (scrollHeight > 0) {
                setProgress((scrollTop / scrollHeight) * 100);
            } else {
                setProgress(0);
            }
        };

        window.addEventListener("scroll", handleScroll, { passive: true });
        handleScroll();

        return () => window.removeEventListener("scroll", handleScroll);
    }, []);

    const activeBlocks = Math.ceil((progress / 100) * TOTAL_BLOCKS);

    return (
        <div className="fixed right-0 top-0 bottom-0 w-4 sm:w-5 bg-[#050505] border-l-2 border-[var(--border-dim)] z-[100] pointer-events-none flex flex-col py-2 px-[4px] gap-[3px]">
            {Array.from({ length: TOTAL_BLOCKS }).map((_, index) => {
                const isActive = index < activeBlocks;

                return (
                    <div
                        key={index}
                        // 'duration-500' adds that smooth, slow fade-in/fade-out
                        className="flex-1 w-full rounded-[1px] transition-all duration-500 ease-out"
                        style={{
                            backgroundColor: isActive ? "rgba(0, 255, 65, 0.85)" : "rgba(0, 255, 65, 0.05)",
                            // Removed the border on inactive blocks so it looks much cleaner
                            border: isActive ? "1px solid rgba(0, 255, 65, 0.6)" : "1px solid transparent",
                            boxShadow: isActive ? "0 0 10px rgba(0, 255, 65, 0.5)" : "none",
                        }}
                    />
                );
            })}
        </div>
    );
}