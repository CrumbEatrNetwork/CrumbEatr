# MODIFICATIONS.md

This document records all modifications made to CrumbEatr in compliance with the GNU General Public License version 3.0.

**CrumbEatr is a derivative work** based on the Taggr project. This project was created by cloning the original Taggr repository at commit `85f0b4e0ed43f96eb4b52747769fdcdc5917b611` on July 13, 2025, and then extensively modifying it to create an independent decentralized social network platform.

All modifications listed below have been made under the terms of GPL v3.0, preserving the original license terms while documenting changes as required by the license.

---

## August 2025: UI/UX Refinements and Content Updates

### August 25-26, 2025

- **PWA Branding Consistency**: Fixed Progressive Web App branding inconsistencies by updating app title from "CRUMBEATR" to "CrumbEatr" in index.html and removing uppercase formatting from dynamic titles. Updated staging banner text to use proper capitalization instead of all caps for improved user experience.
- **Mobile UI Improvements**: Enhanced mobile feed separator styling with thicker borders (1px to 2px) and reduced spacing between feed items (0.5em to 0.2em) for better visual separation and content density on mobile devices.
- **Header Navigation Polish**: Reduced back button spacing from 0.5rem to 0.25rem to prevent header crowding and improve navigation layout on smaller screens.
- **Cross-browser Compatibility**: Fixed Safari text selection issues by adding `-webkit-user-select: text` CSS prefix to selectable elements, ensuring consistent text selection behavior across all browsers.
- **Realm Configuration Fix**: Corrected cleanup penalty field input behavior by changing default value from 10 to 0 and fixing placeholder consistency, improving realm creation user experience.
- **Notification Improvements**: Removed emoji from invite notification messages to maintain professional and consistent messaging across the platform.
- **Test Suite Updates**: Updated E2E tests to reflect corrected app title branding ("CRUMBEATR" to "CrumbEatr") ensuring test accuracy.

### August 24, 2025

- **User Reference Updates**: Updated team member references throughout codebase - changed developer reference to "Y" and growth & marketing member to "SubZero" across whitepaper, backend minting logic, frontend token display, and test assertions
- **Internet Identity 2.0 Upgrade**: Updated authentication system from Internet Identity 1.0 to 2.0, changing identity provider URL from `https://identity.ic0.app` to `https://id.ai` for production and staging deployments. This enables improved user experience with Google login support, elimination of anchor numbers for new users, and enhanced passkey authentication flows.

### August 19-21, 2025

- **PWA and Landing Page Updates**: Updated Progressive Web App title and refined landing page messaging for better user onboarding
- **Social Media Integration**: Updated social media description to "Break free from the algorithm" to better reflect platform philosophy
- **GitHub Link Removal**: Removed GitHub footer link from the main application interface
- **Visual Polish**: Replaced party emoji with sunglasses emoji in welcome notifications for consistent branding
- **Code Quality**: Applied Prettier formatting to frontend codebase for consistency

### August 18-19, 2025

- **Infrastructure Updates**: Updated canister IDs throughout codebase to reflect CrumbEatr deployment infrastructure
- **Icon Consistency**: Replaced balloon icons with infinity symbols for proposals menu, updated inbox empty message emoji from rocket to UFO
- **Documentation**: Removed outdated CrumbEatr Network Neuron and Bot sections from whitepaper following feature removals
- **Testing**: Fixed E2E sanity check tests and wallet tests to use correct canister ID prefixes

### August 13-16, 2025

- **Visual Identity**: Updated social media image for rebrand with better quality, improved favicon design and backend token metadata
- **Security Enhancement**: Removed password authentication in production builds to rely solely on Internet Identity
- **Theme System**: Fixed default theme mismatch by setting black as default applied theme
- **UI Polish**: Fixed inbox feed item button borders, replaced pirate flag emoji with infinity symbol for consistency

### August 6-12, 2025

- **Platform Simplification**: Removed bot functionality and NNS neuron functionality to simplify platform architecture
- **Development Infrastructure**: Improved E2E test setup reliability with better error handling
- **Code Quality**: Applied comprehensive formatting fixes with Prettier and fixed Rust clippy warnings
- **Dependency Management**: Downgraded idna_adapter to 1.1.0 for Rust 1.78.0 compatibility
- **Testing Improvements**: Fixed E2E test text matching and semantic HTML checks

### August 2-6, 2025

- **Major Dependency Upgrade**: Upgraded dependencies to match Taggr February 2024 version, including React, @dfinity packages, and build tools
- **Development Configuration**: Added staging network support to Candid metadata, fixed NNS extension compatibility
- **Build System**: Added global Candid metadata configuration to dfx.json, fixed dependency upgrade configuration

## July 2025: Initial CrumbEatr Creation and Complete Rebranding

### July 23-28, 2025

- **Infrastructure**: Updated footer copyright year from 2021 to 2025, updated staging token symbol from STAGG to SCRUM
- **Terminology**: Renamed "stalwart" terminology to "arbiter" throughout codebase for platform-specific language
- **Development Workflow**: Fixed DFX PATH issues in GitHub Actions, updated local development port configuration
- **UI Enhancements**: Added sticky hover effects for reaction buttons, reordered header navigation for improved UX

### July 14-22, 2025

- **Visual Identity**: Complete comprehensive rebranding from Taggr to CrumbEatr including logos, colors, and branding elements
- **Frontend Overhaul**: Updated loading screen styling, fixed visual artifacts on post containers, enhanced button styling
- **Color Scheme**: Updated clickable link colors to electric orange, fixed logo color adaptation for theme switching
- **Typography**: Updated frontend typography system and favicon implementation
- **Configuration**: Added separate token_name field to Config struct, updated Cargo.lock for rebranding

### July 13, 2025 - Project Creation

- **Base Commit**: `85f0b4e0ed43f96eb4b52747769fdcdc5917b611` - "Add project attribution and update README for CrumbEatr rebranding"
- **Initial Clone**: Cloned Taggr repository and began transformation into CrumbEatr
- **Project Foundation**: Established CrumbEatr as an independent derivative work under GPL v3.0

---

## Future Modifications

To maintain GPL 3.0 compliance, all future modifications should be documented in this file by adding new entries at the top of this document in reverse chronological order. Each entry should include:

- Date of modification
- General description of changes made
- Rationale for the changes (when significant)

**For Contributors**: When adding new modifications, always insert them at the top of the most recent time period section, or create a new time period section if significant time has passed. This maintains the reverse chronological order while keeping related changes grouped together.

---

_This modification documentation is maintained in compliance with the GNU General Public License version 3.0, Section 5(a), which requires that modified works carry prominent notices stating that modifications were made and providing relevant dates._
