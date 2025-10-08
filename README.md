# PkceDemoApp

This is a demo ASP.NET MVC application that demonstrates the OAuth 2.0 Authorization Code Flow with PKCE (Proof Key for Code Exchange) using Azure Active Directory (Azure AD).

## Features
- Login with Azure AD using PKCE
- Secure token exchange
- Session-based authentication
- Logout functionality

## Prerequisites
- .NET Framework (suitable for ASP.NET MVC projects)
- Azure AD tenant
- An app registration in Azure AD (Web or SPA)

## Configuration
1. **Register an application in Azure AD**
   - Set the redirect URI to `http://localhost:5000` (or your app's URL).
   - Note the Client ID, Client Secret, and Tenant ID.
2. **Update the following in `HomeController.cs`:**
   - `ClientId`: Your Azure AD Application (client) ID
   - `ClientSecret`: Your Azure AD Application secret
   - `TenantId`: Your Azure AD tenant ID
   - `RedirectUri`: The redirect URI registered in Azure AD

## Authentication Flow
1. **Login**
   - User clicks login.
   - The app generates a PKCE code verifier and challenge.
   - The app redirects the user to Azure AD's authorization endpoint with PKCE parameters.
2. **Authorization**
   - User authenticates with Azure AD and consents.
   - Azure AD redirects back to the app with an authorization code.
3. **Token Exchange**
   - The app exchanges the authorization code and code verifier for tokens (ID token, access token).
   - Tokens are stored in the session.
4. **Session**
   - If authenticated, the user sees the home page.
   - If not, the login page is shown.
5. **Logout**
   - Session is cleared and the user is redirected to the login page.

## Code Structure
- `Controllers/HomeController.cs`: Implements the PKCE OAuth flow and session management.
- `Views/Home/Login.cshtml`: Login page.
- `Views/Home/Home.cshtml`: Home page for authenticated users.
- `Views/Home/Callback.cshtml`: Displays errors or token exchange results.

## Running the App
1. Build and run the project in Visual Studio or your preferred IDE.
2. Navigate to `http://localhost:5000`.
3. Click login to start the authentication flow.

## Notes
- This demo uses TempData and session for PKCE and token storage.
- For production, secure your secrets and use HTTPS.



