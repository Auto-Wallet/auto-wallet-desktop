import { useEffect, useState } from "react";

export function BrowserUrlInput({
  currentUrl,
  onFocusChange,
  onNavigate,
  onError,
}: {
  currentUrl: string;
  onFocusChange: (focused: boolean) => void;
  onNavigate: (url: string) => Promise<void>;
  onError: (error: unknown) => void;
}) {
  const [url, setUrl] = useState(currentUrl);

  useEffect(() => setUrl(currentUrl), [currentUrl]);

  return (
    <input
      value={url}
      spellCheck={false}
      onChange={(event) => setUrl(event.target.value)}
      onKeyDown={async (event) => {
        if (event.key !== "Enter" || event.nativeEvent.isComposing) return;
        event.preventDefault();
        try {
          const input = event.currentTarget.value.trim();
          const hasScheme = /^[a-z][a-z\d+.-]*:/i.test(input);
          const isHostWithPort = /^[^/?#:\s]+:\d+(?:[/?#]|$)/.test(input);
          const target = new URL(hasScheme && !isHostWithPort ? input : `https://${input}`);
          if (target.protocol !== "http:" && target.protocol !== "https:") {
            throw new Error("Only HTTP and HTTPS addresses are supported");
          }
          await onNavigate(target.href);
        } catch (error) {
          onError(error);
        }
      }}
      onFocus={(event) => {
        onFocusChange(true);
        event.target.select();
      }}
      onBlur={() => {
        onFocusChange(false);
        setUrl(currentUrl);
      }}
    />
  );
}
