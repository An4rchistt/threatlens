import { useState } from 'react';
import type { AppProps } from 'next/app';
import Head from 'next/head';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import '../styles/globals.css';

export default function ThreatLensApp({ Component, pageProps }: AppProps) {
  // Created in state so each browser session gets exactly one client and the
  // cache is never shared across requests during SSR.
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // Scans are expensive; never refetch one implicitly.
            retry: 1,
            refetchOnWindowFocus: false,
            staleTime: 30_000,
          },
          mutations: {
            retry: 0,
          },
        },
      })
  );

  return (
    <QueryClientProvider client={queryClient}>
      <Head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="color-scheme" content="dark" />
        <meta name="theme-color" content="#0f172a" />
        <meta
          name="description"
          content="ThreatLens - AI-powered web threat detection and phishing analysis for security analysts."
        />
        <meta name="robots" content="noindex, nofollow" />
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <title>ThreatLens | Phishing Analysis & Web Threat Engine</title>
      </Head>
      <Component {...pageProps} />
    </QueryClientProvider>
  );
}
