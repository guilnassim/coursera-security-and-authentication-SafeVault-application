# SafeVault

SafeVault is a **security‑focused ASP.NET Core (.NET 8) sample application** designed to demonstrate secure coding practices aligned with **Clean Architecture**, **SOLID**, and the **OWASP Top 10**.

The project showcases how to **prevent SQL injection and XSS**, and how to implement **robust authentication and authorization** using ASP.NET Identity, JWT, and role‑based access control.

---

## Architecture

The solution is organized into four layers:

- **Domain** – Core entities and value objects (`UserRecord`) enforcing invariants.
- **Application** – Use cases, services, DTOs, input sanitization, and security abstractions.
- **Infrastructure** – Encryption, EF Core InMemory (application DB), ASP.NET Identity with a separate InMemory store, repositories, JWT issuance.
- **Presentation** – ASP.NET Core MVC/Razor Pages, controllers, views, anti‑forgery protection, and authorization policies.

---

## Vulnerabilities Identified

The initial design exposed common web‑application risks:

- **SQL Injection** due to the possibility of unsafe query construction.
- **Cross‑Site Scripting (XSS)** from unvalidated and unencoded user input.
- **Weak Input Validation**, allowing unexpected or malicious characters.
- **Missing Authorization Controls**, with no role‑based restrictions.

---

## Fixes Applied

To mitigate these issues, the following measures were implemented:

- **Parameterized Queries**
  - All data access uses **EF Core LINQ**, which generates parameterized SQL and prevents injection.

- **Input Validation & Sanitization**
  - Strict allow‑list validation and a shared `InputSanitizer`.
  - Invalid data is rejected before reaching the domain.

- **XSS Protection**
  - Razor’s default HTML encoding is used for all output.
  - Reflected user input is explicitly encoded when rendered.

- **Authentication & Authorization**
  - **ASP.NET Identity** with secure password hashing.
  - **JWT‑based authentication** for secure API communication.
  - **Role‑Based Access Control (RBAC)** with Admin, User, and Guest roles.
  - **Authorization policies** and **anti‑forgery tokens** for sensitive endpoints.

---

## Testing

Security‑oriented **xUnit tests** validate the protections:

- SQL injection payloads are rejected.
- XSS payloads fail validation and are never rendered.
- Valid registration and login succeed.
- Role‑restricted endpoints are inaccessible to unauthorized users.

These tests act as regression safeguards against future vulnerabilities.

---

## How Copilot Assisted

Copilot was used as a **secure development assistant** to:

- Highlight potentially insecure patterns in validation, queries, and output handling.
- Guide refactoring toward **Clean Architecture** boundaries.
- Suggest **OWASP‑aligned mitigations** for injection and XSS risks.
- Help design focused tests that simulate real‑world attack scenarios.

All code and security decisions were **reviewed and validated by the developer**.

---

## Disclaimer

SafeVault is a **demonstration project**. Production systems should additionally include persistent storage, secure secret management, monitoring, rate limiting, and regular security reviews.