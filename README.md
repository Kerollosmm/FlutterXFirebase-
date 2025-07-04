# AuthGuard - Firebase Authentication

Flutter application implementing Firebase authentication with complete register/login flow.

## Project Structure (lib folder)

The project follows a modular structure with separation of concerns:

```
lib/
├── constants/       # Application constants
├── enums.dart       # Action enums (e.g., MenuAction.logout)
├── firebase_options.dart # Firebase platform configurations
├── main.dart        # App entry point with Firebase initialization
├── page/            # Main application pages
├── regiter&logIn page/ # Complete authentication flow:
│   ├── accounAnalyz.dart # Account analysis screen
│   ├── loginpadge.dart   # Login screen
│   └── registerScreen.dart # Registration screen
├── services/        # Business logic services:
│   └── auth/        # Authentication services
│       ├── Auth_servies.dart         # Auth service interface
│       ├── auth_exception.dart       # Custom auth exceptions
│       ├── auth_provider.dart        # Auth provider
│       ├── auth_user.dart            # User model
│       └── firebase_auth_provider.dart # Firebase implementation
└── widgets/         # Reusable UI components:
    ├── Botton.dart         # Custom buttons
    ├── ErrorDialog.dart    # Error dialogs
    ├── HeaderSection.dart  # Section headers
    ├── MyAlert.dart        # Alert dialogs
    ├── customFeild.dart    # Input fields
    ├── register_card.dart  # Registration card
    └── snakbar.dart        # Snackbar notifications
```

## Key Features
- Firebase authentication (email/password)
- Complete registration and login flow
- Account management
- Error handling with custom dialogs
- Reusable UI components

## Initial Commit
`bb7492525f38cc513d238d0bff84b11cf3c1d029` - Initial commit of AuthGuard project

## Getting Started

This project is a starting point for a Flutter application.

A few resources to get you started if this is your first Flutter project:

- [Lab: Write your first Flutter app](https://docs.flutter.dev/get-started/codelab)
- [Cookbook: Useful Flutter samples](https://docs.flutter.dev/cookbook)

For help getting started with Flutter development, view the
[online documentation](https://docs.flutter.dev/), which offers tutorials,
samples, guidance on mobile development, and a full API reference.
