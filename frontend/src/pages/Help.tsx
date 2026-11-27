import { PageHeader } from '../ui'

const TERMS = [
  ['Shadow API', 'A live API that is not in the specification.'],
  ['Zombie API', 'A deprecated or older API version that still responds.'],
  ['BOLA / IDOR', 'One user can read an object that belongs to another user.'],
  ['Function-level access (BFLA)', 'A normal user can call an administrative function.'],
  ['Identifier link', 'One API returns an identifier that another API accepts.'],
  ['Attack path', 'A chain of requests that all succeeded, where earlier steps supply the identifiers needed later.'],
  ['Confirmed / Needs review', 'Confirmed findings have direct comparison evidence. Review findings need a person to decide.'],
]

export default function Help() {
  return (
    <div className="narrow">
      <PageHeader heading="Guide" sub="How to get accurate results, and what the tool does not do" />
      <section className="card">
        <h2>Get accurate results</h2>
        <ol>
          <li>Upload the OpenAPI specification. Without it, nothing can be called a shadow API.</li>
          <li>Add <strong>two normal users</strong> that each own some data, such as orders or profiles.</li>
          <li>Add an administrator account to confirm admin-route findings.</li>
          <li>Upload a HAR capture recorded while using the application. It gives the scanner real paths.</li>
          <li>Mark intentionally public routes with <code>security: []</code> in the specification.</li>
          <li>Review each finding’s evidence before you act on it.</li>
        </ol>
      </section>
      <section className="card">
        <h2>Terms</h2>
        <dl>{TERMS.map(([term, text]) => <div key={term} className="term"><dt><strong>{term}</strong></dt><dd>{text}</dd></div>)}</dl>
      </section>
      <section className="card">
        <h2>Limitations</h2>
        <ul>
          <li>Only GET requests are sent, so flaws in POST, PUT, PATCH and DELETE are not tested.</li>
          <li>The crawler reads HTML and JavaScript files. It does not run a browser. Use a HAR capture for apps that load routes dynamically.</li>
          <li>Ownership is inferred by comparing what different users see. If both test users see identical data, ownership cannot be inferred.</li>
          <li>GraphQL, gRPC and WebSocket APIs are not analysed.</li>
          <li>Expired-token handling, injection and rate-limit flaws are not tested.</li>
          <li>No findings does not mean that an application is secure.</li>
        </ul>
      </section>
    </div>
  )
}
