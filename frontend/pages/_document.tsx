import Document, {
  DocumentContext,
  DocumentInitialProps,
  Head,
  Html,
  Main,
  NextScript,
} from 'next/document';

class ThreatLensDocument extends Document {
  static async getInitialProps(ctx: DocumentContext): Promise<DocumentInitialProps> {
    return Document.getInitialProps(ctx);
  }

  render() {
    return (
      // `lang` and the dark class are set here so assistive tech and the
      // first paint both get the right context.
      <Html lang="en" className="dark">
        <Head />
        <body className="bg-slate-900 text-slate-100">
          <Main />
          <NextScript />
        </body>
      </Html>
    );
  }
}

export default ThreatLensDocument;
