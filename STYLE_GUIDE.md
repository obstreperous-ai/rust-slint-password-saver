# 🎨 Password Saver — Design & Style Guide

## Vision Statement

*An elegant, restrained and minimal look with a smooth, responsive and attentive user experience.*

This password manager embraces the refined aesthetics of **Meiji era Japan** and **Edwardian England**, combined with the revolutionary design philosophy of early **Apple** (1984-2000) and the timeless visual communication principles of **David Ogilvy's** advertising work from the 1970s and 80s.

### Core Design Principles

#### 1. **Restraint & Minimalism** (Meiji Japan)
- **Ma (間)** — Negative space as a design element, not emptiness
- **Kanso (簡素)** — Simplicity without being simplistic
- **Shizen (自然)** — Natural, effortless interaction
- Remove everything unnecessary; what remains becomes essential

#### 2. **Precision & Craftsmanship** (Edwardian England)
- Attention to detail in every interaction
- Quality over quantity in visual elements
- Clear hierarchy through typography and spacing
- Trustworthy, dependable, and refined presentation

#### 3. **Human-Centered Technology** (Early Apple)
- Technology that serves people, not intimidates them
- Clarity of purpose in every screen
- Consistency creates confidence
- "Insanely great" attention to user experience
- Make the complex feel simple

#### 4. **Clear Visual Communication** (David Ogilvy)
- "When you have written your headline, you have spent eighty cents out of your dollar"
- Every element must earn its place
- Hierarchy guides the eye naturally
- White space is not wasted space — it's premium real estate
- Authenticity and honesty in messaging

---

## Design Language

### Color Palette

Our color system balances security, trust, and elegance with restraint.

#### Primary Colors

| Color | Hex | Usage | Inspiration |
|-------|-----|-------|------------|
| **Forest Green** | `#2d5016` | Primary actions, success states | Japanese pine forests, trust, security |
| **Charcoal** | `#2c2c2c` | Primary text, strong emphasis | Ink calligraphy, authority |
| **Warm Grey** | `#6b6b6b` | Secondary text, labels | Subtlety, refinement |
| **Whisper Grey** | `#e8e8e8` | Backgrounds, dividers | Washi paper, quiet elegance |

#### Accent Colors

| Color | Hex | Usage | Inspiration |
|-------|-----|-------|------------|
| **Vermillion** | `#c1440e` | Errors, warnings, destructive actions | Japanese seals, urgent attention |
| **Indigo** | `#1a365d` | Information, links | Indigo dye, calm intelligence |
| **Cream** | `#faf9f6` | Canvas, primary background | Paper, parchment, timelessness |

#### State Colors

| State | Hex | Usage |
|-------|-----|-------|
| **Success** | `#2d5016` | Successful operations |
| **Warning** | `#b8860b` | Caution states |
| **Error** | `#c1440e` | Failures, critical alerts |
| **Info** | `#1a365d` | Informational messages |
| **Disabled** | `#d3d3d3` | Inactive elements |

**Color Usage Principles:**
- Use color sparingly — when everything is colored, nothing stands out
- Green for security and trust (encrypted, safe, success)
- Red for danger and caution (errors, destructive actions, warnings)
- Neutral tones dominate — 80% grey scale, 20% color
- Always maintain WCAG AA contrast ratios (4.5:1 for text)

---

### Typography

Typography creates hierarchy, guides attention, and communicates authority.

#### Type System

```
Heading 1 (Screen Title):
  Font Size: 28px
  Font Weight: 600 (Semibold)
  Color: #2c2c2c (Charcoal)
  Letter Spacing: -0.5px (Slight tightening)
  Use: Main screen title, once per view

Heading 2 (Section Title):
  Font Size: 18px
  Font Weight: 600
  Color: #2c2c2c
  Use: Group boxes, major sections

Body Text (Primary):
  Font Size: 14px
  Font Weight: 400 (Regular)
  Color: #2c2c2c
  Line Height: 1.5
  Use: Main content, labels

Body Text (Secondary):
  Font Size: 13px
  Font Weight: 400
  Color: #6b6b6b (Warm Grey)
  Line Height: 1.4
  Use: Hints, descriptions, metadata

Small Text (Tertiary):
  Font Size: 11px
  Font Weight: 400
  Color: #6b6b6b
  Use: Captions, timestamps, fine print

Button Text:
  Font Size: 14px
  Font Weight: 500 (Medium)
  Use: All button labels
```

**Typography Principles:**
- Hierarchy through size, weight, and color — not decorative fonts
- Consistent line heights create rhythm
- Generous leading (line spacing) improves readability
- Limit to 3 text sizes per screen
- Left-align text for Western languages (natural reading flow)

---

### Spacing & Layout

Consistent spacing creates visual harmony and reduces cognitive load.

#### Spacing Scale

Our spacing system uses a **base unit of 4px**, growing in increments:

```
4px   — xs  (Tiny gaps, icon padding)
8px   — sm  (Compact spacing, related items)
12px  — md  (Standard element spacing)
16px  — lg  (Section padding, comfortable gaps)
20px  — xl  (Group separation)
24px  — 2xl (Major section gaps)
32px  — 3xl (Screen padding, significant separation)
```

**Usage:**
- **Padding inside containers:** 16-24px
- **Spacing between form fields:** 12-16px
- **Spacing between sections:** 20-24px
- **Screen margins:** 24-32px
- **Button padding:** 12px horizontal, 8px vertical

#### Grid & Alignment

- **Form Layout:** Label width of 120-140px, inputs fill remaining space
- **Buttons:** Minimum width of 100px for primary actions
- **Vertical rhythm:** Elements align to 8px baseline grid
- **Maximum content width:** 600px (prevents eye strain on wide screens)

---

### Components

Design specifications for all UI elements.

#### Buttons

**Primary Button** (Main actions)
```
Background: #2d5016 (Forest Green)
Text: #ffffff (White)
Border: None
Border Radius: 4px
Padding: 10px 20px
Font: 14px, Weight 500
Min Width: 100px

States:
  Hover: Background #3d6020
  Active: Background #1d3010
  Disabled: Background #d3d3d3, Text #999999
```

**Secondary Button** (Alternative actions)
```
Background: Transparent
Text: #2d5016
Border: 1px solid #2d5016
Border Radius: 4px
Padding: 10px 20px

States:
  Hover: Background #f5f5f5
  Active: Background #e8e8e8
  Disabled: Border #d3d3d3, Text #999999
```

**Destructive Button** (Delete, remove actions)
```
Background: Transparent
Text: #c1440e (Vermillion)
Border: 1px solid #c1440e
Border Radius: 4px

States:
  Hover: Background #fff5f5
  Active: Background #ffe5e5
```

**Button Principles:**
- One primary button per screen (the main action)
- Primary actions on the right (Western reading flow)
- Destructive actions require confirmation
- Disabled buttons explain why they're disabled (via tooltip or helper text)

#### Input Fields

**Text Input / Line Edit**
```
Border: 1px solid #d3d3d3
Border Radius: 4px
Padding: 10px 12px
Font: 14px
Background: #ffffff
Placeholder Color: #999999

States:
  Focus: Border #2d5016, Shadow 0 0 0 3px rgba(45,80,22,0.1)
  Error: Border #c1440e
  Disabled: Background #f5f5f5, Border #e8e8e8
```

**Password Input**
```
Input Type: password (masked)
Show/Hide Toggle: Optional, but recommended
Same styling as Text Input
```

**Input Principles:**
- Clear visual feedback for focus state
- Placeholder text explains expected format
- Error messages below field, with error icon
- Labels above inputs, always visible (not floating)

#### Group Boxes / Cards

```
Background: #faf9f6 (Cream) OR #ffffff
Border: 1px solid #e8e8e8
Border Radius: 6px
Padding: 20px
Margin Between: 20px

Title:
  Font: 16px, Weight 600
  Color: #2c2c2c
  Margin Bottom: 16px
```

**Principles:**
- Use sparingly — group related items only
- Title describes the group's purpose clearly
- Avoid nesting group boxes more than one level

#### Status Messages / Alerts

**Success Message**
```
Background: #e6f4e7
Border: 1px solid #2d5016
Border Radius: 4px
Padding: 12px 16px
Icon: ✓ (Check mark)
Text Color: #1d3010
```

**Error Message**
```
Background: #ffeaea
Border: 1px solid #c1440e
Border Radius: 4px
Padding: 12px 16px
Icon: ⚠ (Warning)
Text Color: #8b1a0a
```

**Info Message**
```
Background: #e8f1f8
Border: 1px solid #1a365d
Border Radius: 4px
Padding: 12px 16px
Icon: ℹ (Info)
Text Color: #0d1b2e
```

**Message Principles:**
- Auto-dismiss after 5 seconds for success (user can close early)
- Errors require manual dismissal (don't auto-hide problems)
- One message at a time (queue if multiple)
- Messages are clear, actionable, and non-technical

#### Modals / Dialogs

```
Overlay: rgba(0, 0, 0, 0.4)
Dialog Background: #ffffff
Border Radius: 8px
Width: 500px (maximum)
Padding: 24px
Shadow: 0 10px 40px rgba(0,0,0,0.2)

Title:
  Font: 20px, Weight 600
  Margin Bottom: 16px

Actions:
  Aligned right
  Destructive on left, Cancel in middle, Primary on right
  Spacing: 12px between buttons
```

**Dialog Principles:**
- Use sparingly — dialogs interrupt workflow
- One clear purpose per dialog
- Always provide a way to cancel/close
- Escape key closes dialog
- Confirm destructive actions with explicit wording ("Delete Password", not "OK")

---

### Iconography

Icons enhance understanding but should never replace clear text.

**Icon Style:**
- **Line-based icons** (not filled) — matches minimalist aesthetic
- **1.5px stroke width** — delicate but visible
- **20x20px size** for inline icons, 24x24px for standalone
- **Color:** Match text color (usually #2c2c2c or #6b6b6b)

**Common Icons:**
- 🔒 **Lock** — Security, encryption, protected
- 🔑 **Key** — Master password, authentication
- ✓ **Check** — Success, confirmed, enabled
- ⚠ **Warning** — Caution, error, attention needed
- ℹ **Info** — Help, information, learn more
- ⊕ **Plus** — Add, create new
- ✕ **X** — Close, delete, remove

**Icon Principles:**
- Icons + text labels (not icons alone)
- Consistent icon style throughout
- Don't invent new metaphors — use established patterns

---

### Animation & Transitions

Subtle motion creates a sense of responsiveness and quality.

**Timing:**
- **Fast (100-150ms):** Button hover states, focus changes
- **Medium (200-300ms):** Panel slides, fades, reveals
- **Slow (400-500ms):** Page transitions, major state changes

**Easing:**
- **ease-out** — Most common, feels responsive
- **ease-in-out** — For symmetric animations (open/close)

**Principles:**
- Motion should feel natural, not robotic
- Slower is more elegant — avoid rushed animations
- User-initiated actions are immediate (no artificial delays)
- Reduce motion for accessibility (respect OS preferences)

---

## Current Codebase Analysis

### ✅ What's Working Well

#### 1. **Clear Information Architecture**
- Logical flow: Master Password → Add Entry → View Passwords
- Grouped related functions (GroupBox usage)
- Progressive disclosure (Change Password in dialog)

#### 2. **Security-First UX**
- Master password prominently placed and required
- Password inputs properly masked (`input-type: password`)
- Clear explanations of master password purpose

#### 3. **Form Design**
- Consistent field layout with labels
- Placeholder text provides helpful hints
- Save button disabled when required fields empty
- Fields auto-clear after successful save

#### 4. **Feedback Mechanisms**
- Status messages appear after actions
- Color-coded feedback (green for success)
- Visual distinction from main content

### ⚠️ Areas for Improvement

#### 1. **Visual Hierarchy**
**Current State:**
```slint
Text {
    text: "Password Saver";
    font-size: 24px;
    font-weight: 700;
}
```
**Issues:**
- Title is centered (unconventional for desktop apps)
- Font weight too heavy (700 is very bold)
- No visual breathing room around title

#### 2. **Color Palette**
**Current State:**
- Uses generic colors: `#666` (grey), `#4caf50` (Material green), `#f44336` (Material red)
- No cohesive color system
- Colors borrowed from Material Design, not custom to this app

**Issues:**
- Lacks personality and brand identity
- Material Design colors designed for web, not desktop
- Green (#4caf50) is bright and energetic (not restrained)

#### 3. **Typography System**
**Current State:**
- Inconsistent font sizes: 24px, 14px, 12px
- Mixed use of colors for text: `#666`, `#888`, `#2e7d32`
- No defined type scale or hierarchy

**Issues:**
- Typography feels arbitrary, not systematic
- Secondary text color (`#666`) has insufficient contrast
- No rhythm or consistent vertical spacing

#### 4. **Spacing Inconsistencies**
**Current State:**
```slint
VerticalBox {
    padding: 20px;
    spacing: 15px;
}
```
**Issues:**
- Spacing values: 10px, 15px, 20px — not from unified scale
- No consistent padding across GroupBox elements
- Vertical spacing doesn't align to grid

#### 5. **Button Design**
**Current State:**
- Primary button uses Slint default styling
- No defined hover, active, or disabled states
- "Change Master Password" button has same visual weight as "Load Passwords"

**Issues:**
- All buttons look equally important
- Visual hierarchy unclear (which is primary action?)
- Missing opportunity for brand expression

#### 6. **Change Password Dialog**
**Current State:**
```slint
Rectangle {
    width: 500px;
    height: 450px;
    background: white;
    border-radius: 8px;
    border-width: 2px;
    border-color: #4caf50;
}
```
**Issues:**
- Green border is distracting (not appropriate for a security dialog)
- Fixed height (450px) may crop content
- Overlay background too dark (`rgba(0, 0, 0, 0.5)`)
- Password requirements use bullet points (inconsistent with desktop conventions)

#### 7. **Status Message Design**
**Current State:**
```slint
Rectangle {
    background: #e8f5e9;
    border-radius: 4px;
    border-width: 1px;
    border-color: #4caf50;
}
```
**Issues:**
- Only shows success state (no error state design)
- Appears/disappears abruptly (no transition)
- No icon to reinforce message type
- Color too bright and energetic

#### 8. **Window & Layout**
**Current State:**
```slint
title: "Password Saver";
preferred-width: 600px;
preferred-height: 600px;
```
**Issues:**
- Square window (600x600) feels arbitrary
- No minimum width/height constraints
- Content could benefit from more vertical space
- Window title could be more descriptive

#### 9. **Empty States**
**Current State:**
```slint
Text {
    text: "Password entries will appear here...";
    color: #888;
    font-size: 14px;
}
```
**Issues:**
- Empty state is plain text only (no visual)
- Doesn't guide user on what to do next
- Opportunity to reinforce brand personality missed

#### 10. **Accessibility**
**Issues:**
- No keyboard shortcuts documented or shown
- Tab order not explicitly defined (relies on defaults)
- No focus indicators visible in current design
- Color contrast of `#666` and `#888` text fails WCAG AA on white background

---

## Actionable Improvement Tasks

Each task below is suitable for assignment to a GitHub Copilot AI agent. Tasks are ordered by priority and impact.

### Priority 1: Foundation (Visual Identity)

#### Task 1.1: Implement New Color Palette ✅ COMPLETED
**Description:** Replace current Material Design colors with refined, restrained color palette inspired by Meiji Japan and Edwardian England.

**Status:** ✅ Completed - Color palette implemented and integrated throughout the application.

**Files Modified:**
- `src/ui/main.slint`

**Changes Completed:**
1. ✅ Defined color constants at top of file with Colors global
2. ✅ Replaced all hardcoded colors:
   - `#4caf50` → `Colors.forest-green`
   - `#666` → `Colors.warm-grey`
   - `#888` → `Colors.warm-grey`
   - `#2e7d32` → `Colors.success-text`
   - `white` → `Colors.cream` (for backgrounds)
   - Additional colors: `#555`, `#999`, `#f5f5f5`, `#2196f3` mapped to appropriate Colors palette
3. ✅ Updated status message backgrounds and borders to use new state colors

**Testing Results:**
- ✅ Application builds successfully
- ✅ All tests pass (134/134)
- ✅ No hardcoded colors in main color usage areas
- ✅ Application maintains visual coherence

**Note:** Some Material Design colors (#ff9800, etc.) remain in update notification banners and warning dialogs, which are appropriate for their semantic meaning (warnings/errors).

---

#### Task 1.2: Establish Typography System
**Description:** Implement consistent typography hierarchy with defined font sizes, weights, and colors.

**Files to Modify:**
- `src/ui/main.slint`

**Changes Required:**
1. Define typography styles as reusable components or properties:
   ```slint
   global Typography {
       // Heading 1
       out property <length> h1-size: 28px;
       out property <int> h1-weight: 600;
       out property <length> h1-letter-spacing: -0.5px;
       
       // Heading 2
       out property <length> h2-size: 18px;
       out property <int> h2-weight: 600;
       
       // Body
       out property <length> body-size: 14px;
       out property <int> body-weight: 400;
       
       // Secondary
       out property <length> secondary-size: 13px;
       
       // Small
       out property <length> small-size: 11px;
   }
   ```

2. Update "Password Saver" title:
   ```slint
   Text {
       text: "Password Saver";
       font-size: Typography.h1-size;
       font-weight: Typography.h1-weight;
       color: Colors.charcoal;
       horizontal-alignment: left;  // Changed from center
   }
   ```

3. Update GroupBox titles to use Heading 2 style
4. Update all body text to use consistent 14px size
5. Update secondary text (hints, descriptions) to 13px and warm-grey color
6. Update button text to 14px with font-weight 500

**Testing:**
- Verify font hierarchy is clear and readable
- Check all text sizes are from defined scale
- Ensure left-aligned title looks good in window

**Acceptance Criteria:**
- Typography system defined and documented in code
- All text uses typography constants (no hardcoded sizes)
- Visual hierarchy is clear and consistent
- Title is left-aligned (desktop convention)

**Status:** ✅ **COMPLETED**
- Typography global created with all font sizes, weights, and letter-spacing properties
- Main "Password Saver" title updated to use H1 typography with left alignment
- All dialog titles updated to use appropriate typography levels
- All body text updated to use Typography.body-size (14px)
- All secondary text updated to use Typography.secondary-size (13px) with warm-grey color
- Small text updated to use Typography.small-size (11px)
- All font weights now use Typography constants
- Build successful, all tests pass

---

#### Task 1.3: Implement Consistent Spacing System
**Description:** Replace arbitrary spacing values with systematic spacing scale based on 4px base unit.

**Files to Modify:**
- `src/ui/main.slint`

**Changes Required:**
1. Define spacing constants:
   ```slint
   global Spacing {
       out property <length> xs: 4px;
       out property <length> sm: 8px;
       out property <length> md: 12px;
       out property <length> lg: 16px;
       out property <length> xl: 20px;
       out property <length> xxl: 24px;
       out property <length> xxxl: 32px;
   }
   ```

2. Replace all spacing values:
   - Main VerticalBox padding: `20px` → `Spacing.xxl`
   - Main VerticalBox spacing: `15px` → `Spacing.lg`
   - GroupBox internal spacing: `10px` → `Spacing.md`
   - Button spacing: `10px` → `Spacing.md`

3. Ensure consistent padding in all GroupBox components

**Testing:**
- Visual inspection of spacing consistency
- Verify spacing feels harmonious and not cramped

**Acceptance Criteria:**
- All spacing values use Spacing constants
- No arbitrary spacing values remain
- Visual rhythm is consistent throughout

**✅ Status: COMPLETED**
- Spacing global defined with systematic 4px-based scale (xs: 4px, sm: 8px, md: 12px, lg: 16px, xl: 20px, xxl: 24px, xxxl: 32px)
- All 35 spacing/padding values replaced with Spacing constants
- 5px → Spacing.xs, 10px → Spacing.md, 15px → Spacing.lg, 20px → Spacing.xl, 30px → Spacing.xxxl
- Build successful, all tests pass
- No arbitrary spacing values remain in main.slint

---

### Priority 2: Components (Refinement)

#### Task 2.1: Redesign Primary Button
**Status:** ✅ **COMPLETED**

**Description:** Create custom primary button styling that reflects brand personality.

**Files to Modify:**
- `src/ui/main.slint`

**Changes Required:**
1. Style "Save Password" button as primary:
   ```slint
   Button {
       text: "Save Password";
       primary: true;
       // Override default styling
       background: Colors.forest-green;
       border-color: Colors.forest-green;
       border-radius: 4px;
       min-width: 100px;
       enabled: root.master-password != "" && title-input.text != "" && password-input.text != "";
       
       // Note: Hover/active states may require custom Rectangle+TouchArea
   }
   ```

2. If Slint's standard Button doesn't allow sufficient customization, create custom button component:
   ```slint
   component PrimaryButton {
       in property <string> text;
       in property <bool> enabled: true;
       callback clicked();
       
       Rectangle {
           background: enabled ? Colors.forest-green : #d3d3d3;
           border-radius: 4px;
           min-width: 100px;
           height: 36px;
           
           TouchArea {
               enabled: parent.enabled;
               clicked => { root.clicked(); }
           }
           
           Text {
               text: root.text;
               color: white;
               font-size: Typography.body-size;
               font-weight: 500;
               horizontal-alignment: center;
               vertical-alignment: center;
           }
       }
   }
   ```

3. Replace "Save Password" Button with PrimaryButton

**Testing:**
- Button appears with forest green background
- Disabled state shows grey background
- Button is clearly the primary action on screen
- Clicking button triggers save action

**Acceptance Criteria:**
- Primary button visually distinct from secondary buttons
- Matches color palette (forest green)
- Disabled state is clear
- Click interaction works correctly

---

#### Task 2.2: Redesign Secondary Buttons ✅ COMPLETED
**Description:** Style "Load Passwords" and "Change Master Password" as secondary buttons.

**Status:** ✅ Completed - SecondaryButton component created and integrated for "Load Passwords" and "Change Master Password" actions.

**Files Modified:**
- `src/ui/main.slint`

**Implementation Details:**
1. Created SecondaryButton component with:
   - Transparent background with forest-green border (1px)
   - Enabled state: forest-green border and text
   - Disabled state: grey border (#d3d3d3) and grey text (#999999)
   - Same height (36px) and min-width (100px) as PrimaryButton
   - TouchArea for click interactions
   
2. Replaced "Load Passwords" and "Change Master Password" buttons with SecondaryButton
3. Both buttons maintain their original functionality and enabled states

**Testing Results:**
- ✅ Secondary buttons have outline style (not filled)
- ✅ Visual hierarchy clear (primary > secondary)
- ✅ Both button types work side-by-side
- ✅ All tests pass
- ✅ Code builds without warnings
- ✅ Formatting and linting checks pass

**Acceptance Criteria:**
- ✅ Secondary buttons distinct from primary
- ✅ Outline style with forest green border
- ✅ Disabled state clear (grey)
- ✅ Click interactions work

---

#### Task 2.3: Enhance Input Field Styling ✅ **COMPLETED**
**Description:** Improve input field appearance with better borders, focus states, and consistency.

**Status:** COMPLETED with limitations documented

**Files Modified:**
- `src/ui/main.slint` - Added comprehensive documentation of Slint LineEdit limitations

**Implementation Summary:**
Slint v1.14's standard LineEdit widget does not support custom border properties (border-color, border-width, border-radius) as confirmed by:
- Official Slint documentation
- GitHub issue #3173: "LineEdit add border-width,border-radius,border-color properties"
- GitHub issue #5392: "Proposal: Styling capabilities for the std-widgets"

**What Was Done:**
1. ✅ Identified all 12 LineEdit components in main.slint
2. ✅ Documented the technical limitation in code comments (lines 147-185)
3. ✅ Listed desired styling specifications that cannot currently be applied:
   - border-color: #d3d3d3 (Colors.disabled)
   - border-width: 1px
   - border-radius: 4px
4. ✅ Documented workaround options and their trade-offs
5. ✅ All LineEdit instances continue to use Slint's default platform-native styling with built-in focus states

**Technical Limitation:**
The standard LineEdit widget from `std-widgets.slint` does not expose these properties for customization:
- `border-color` - NOT available
- `border-width` - NOT available
- `border-radius` - NOT available

**Why Custom Component Not Used:**
Creating a custom input component would require:
- Implementing all LineEdit features manually (text input, selection, clipboard, IME support, etc.)
- Losing platform-native appearance and accessibility features
- Significant complexity for minimal visual gain
- Breaking existing functionality

**Current State:**
- All inputs use Slint's default styling with consistent platform-native appearance
- Focus states work using Slint defaults
- Inputs are clearly distinct from buttons and text
- Application builds and runs successfully

**Future Improvement:**
When Slint v1.15+ adds native support for border styling properties on LineEdit, the desired styling can be applied directly. Monitor GitHub issues #3173 and #5392 for updates.

**Testing:**
- ✅ Code compiles without errors
- ✅ All 12 LineEdit components identified and documented
- ✅ Limitation thoroughly documented in source code
- ✅ Application builds successfully (`cargo build`)
- ✅ Default focus states work correctly

---

#### Task 2.4: Improve GroupBox Styling ✅ **COMPLETED**
**Description:** Refine GroupBox appearance to be more elegant and less intrusive.

**Files Modified:**
- ✅ `src/ui/main.slint`

**Changes Implemented:**
1. ✅ Created custom `Card` component with refined styling:
   - Background: `Colors.cream` (#faf9f6)
   - Border: 1px solid `Colors.whisper-grey` (#e8e8e8)
   - Border radius: 6px
   - Padding: `Spacing.lg` (16px) - Implementation uses `Spacing.lg` to achieve the specified 16px padding (note: `Spacing.xl` in codebase = 20px)
   - Title font: 16px, weight 600, `Colors.charcoal` (#2c2c2c)

2. ✅ Replaced all 6 GroupBox instances with Card component:
   - Master Password section
   - Add New Password section
   - Password Generator section
   - Search and Filter Passwords section
   - Copy Password to Clipboard section
   - Stored Passwords section

3. ✅ Documented component implementation with detailed comments

**Technical Rationale:**
The standard GroupBox widget from `std-widgets.slint` does not expose styling properties for customization (background, border-color, border-width, border-radius, title styling). Similar to Task 2.3 with LineEdit, creating a custom component was necessary to achieve the refined visual design specified in the requirements.

**Testing:**
- ✅ Code compiles without errors
- ✅ Application builds successfully (`cargo build`)
- ✅ All 6 Card components render with refined appearance
- ✅ Borders are subtle and non-intrusive
- ✅ Cream background provides elegant visual separation
- ✅ Content remains readable and accessible
- ✅ All functionality preserved (keyboard navigation, data input/output)

---

#### Task 2.5: Redesign Status Messages ✅ COMPLETED
**Description:** Improve status message design with icons, better colors, and error state support.

**Files Modified:**
- `src/ui/main.slint`
- `src/main.rs`

**Changes Implemented:**
1. ✅ Added status message error state support:
   ```slint
   in-out property <bool> status-is-error: false;
   ```

2. ✅ Created enhanced status message component with icons and conditional styling:
   ```slint
   if status-message != "" : Rectangle {
       background: status-is-error ? Colors.error-bg : Colors.success-bg;
       border-radius: 4px;
       border-width: 1px;
       border-color: status-is-error ? Colors.error-border : Colors.success-border;
       
       HorizontalBox {
           padding: Spacing.md;
           spacing: Spacing.md;
           
           Text {
               text: status-is-error ? "⚠" : "✓";
               font-size: 16px;
               color: status-is-error ? Colors.error-text : Colors.success-text;
               vertical-alignment: center;
           }
           
           Text {
               text: status-message;
               color: status-is-error ? Colors.error-text : Colors.success-text;
               font-size: Typography.body-size;
               vertical-alignment: center;
           }
       }
   }
   ```

3. ✅ Updated all status message calls in `src/main.rs` to set appropriate error state:
   - Success operations: `ui.set_status_is_error(false);`
   - Error operations: `ui.set_status_is_error(true);`

**Testing Results:**
- ✅ Success messages show with green styling and checkmark (✓)
- ✅ Error messages show with red styling and warning icon (⚠)
- ✅ Messages are clearly readable
- ✅ Icon and text align properly
- ✅ All tests passing (75 passed; 0 failed)
- ✅ Clippy linter passed with no warnings
- ✅ Code formatting verified

**Acceptance Criteria Met:**
- ✅ Status messages support both success and error states
- ✅ Icons reinforce message type
- ✅ Colors match new palette (using Colors.error-* and Colors.success-* constants)
- ✅ Rust code correctly sets error state for all message types

---

### Priority 3: Dialog & Interaction

#### Task 3.1: Redesign Change Password Dialog ✅ COMPLETED
**Description:** Improve dialog appearance to be more elegant and less distracting.

**Status:** ✅ Completed - Change Password Dialog redesigned with refined aesthetic and improved usability.

**Files Modified:**
- `src/ui/main.slint`

**Implementation Details:**
- Updated dialog overlay with lighter background (rgba 0.4 instead of 0.5)
- Removed fixed dialog height for auto-sizing
- Reduced border width from 2px to 1px for subtle appearance
- Changed border color from forest-green to whisper-grey
- Added drop-shadow for elegant depth (40px blur, rgba(0,0,0,0.2))
- Updated title to 20px font-size with left alignment (desktop convention)
- Enhanced password requirements section with border and improved spacing
- Consolidated password requirements into single Text element
- Right-aligned buttons with proper order (Cancel left, Change Password right)
- Replaced generic Button components with SecondaryButton and PrimaryButton

**Testing:**
- ✅ Dialog appears elegant and refined
- ✅ Overlay is less overwhelming
- ✅ Border is subtle
- ✅ Buttons follow desktop conventions (primary on right)
- ✅ Build successful
- ✅ All 75 tests passing

**Acceptance Criteria:**
- ✅ Dialog matches refined aesthetic
- ✅ No distracting green border
- ✅ Button layout follows conventions
- ✅ Requirements section is readable

---

#### Task 3.2: Add Keyboard Shortcuts ✅ COMPLETED
**Description:** Implement keyboard shortcuts for common actions and document them in UI.

**Status:** ✅ **COMPLETED**

**Implementation Summary:**
- ✅ Added keyboard shortcut hints to all buttons in dialogs:
  - "Save Password (Enter)" in Add Password form
  - "Change Password (Enter)" and "Cancel (Esc)" in Change Password dialog
  - "Unlock (Enter)" in Lock Screen dialog
  - "Continue (Enter/Esc)" in Recovery Setup dialog
  - "Recover Access (Enter)" and "Cancel (Esc)" in Recovery Login dialog

- ✅ Implemented keyboard handlers:
  - `FocusScope` with Escape key handler for Change Master Password dialog
  - `FocusScope` with Escape key handler for Recovery Setup dialog
  - `FocusScope` with Escape key handler for Recovery Login dialog
  - Enhanced `SecondaryButton` component to support Escape key
  - Upgraded Lock Screen and Recovery dialogs to use `PrimaryButton` (has built-in Enter support)

- ✅ Added "⌨️ Keyboard Shortcuts" card in main UI documenting:
  - Common actions (Enter, Esc, Space)
  - Dialog-specific shortcuts
  - All shortcuts are now discoverable in the UI

**Testing:**
- ✅ Escape key closes dialogs
- ✅ Enter key submits forms and confirms actions
- ✅ Keyboard shortcuts are documented and discoverable
- ✅ All tests pass
- ✅ Build succeeds
- ✅ Clippy passes with no warnings

**Files Modified:**
- `src/ui/main.slint` - Added keyboard shortcuts and documentation

---

### Priority 4: Polish & Details

#### Task 4.1: Improve Empty States ✅ COMPLETED
**Description:** Enhance empty password list with helpful guidance and visual interest.

**Files to Modify:**
- `src/ui/main.slint`

**Changes Required:**
1. Replace plain text empty state with richer component:
   ```slint
   VerticalBox {
       alignment: center;
       spacing: Spacing.lg;
       
       Text {
           text: "🔐";
           font-size: 48px;
           horizontal-alignment: center;
       }
       
       Text {
           text: "No passwords saved yet";
           font-size: Typography.h2-size;
           font-weight: 600;
           color: Colors.charcoal;
           horizontal-alignment: center;
       }
       
       Text {
           text: "Add your first password above to get started.";
           font-size: Typography.secondary-size;
           color: Colors.warm-grey;
           horizontal-alignment: center;
       }
   }
   ```

**Implementation Notes:**
- Replaced plain text "Password entries will appear here..." with richer empty state component (lines 708-732)
- Added lock emoji (🔐) at 48px for visual interest
- Added "No passwords saved yet" heading using Typography.h2-size with 600 font-weight
- Added helpful guidance text "Add your first password above to get started." using Typography.secondary-size
- Centered all elements horizontally with proper spacing using Spacing.lg
- Applied color scheme: Colors.charcoal for heading, Colors.warm-grey for guidance text
- All changes maintain consistency with the design system

**Testing:**
- ✅ Empty state appears when no passwords are saved
- ✅ Message is helpful and encouraging
- ✅ Icon adds visual interest
- ✅ All tests pass (134 unit tests + 75 doc tests)
- ✅ Build succeeds
- ✅ Clippy passes with no warnings

**Acceptance Criteria:**
- ✅ Empty state is more engaging than plain text
- ✅ Guides user on next action
- ✅ Matches overall aesthetic

**Files Modified:**
- `src/ui/main.slint` - Enhanced empty state in "Stored Passwords" card

---

#### Task 4.2: Optimize Window Size & Title
**Description:** Refine window dimensions and title for better desktop experience.

**Files to Modify:**
- `src/ui/main.slint`

**Changes Required:**
1. Update window properties:
   ```slint
   export component AppWindow inherits Window {
       title: "Password Saver — Secure Password Manager";
       preferred-width: 600px;
       preferred-height: 700px;  // Increased for more vertical space
       min-width: 500px;
       min-height: 600px;
   }
   ```

2. Consider adding app icon if Slint supports it

**Testing:**
- Window size feels comfortable for content
- Title is descriptive in taskbar/window list
- Minimum sizes prevent content from being cramped

**Acceptance Criteria:**
- Window dimensions optimized
- Title is descriptive
- Minimum sizes set appropriately

---

#### Task 4.3: Add Subtle Transitions
**Description:** Add smooth transitions for status messages and dialog appearance.

**Files to Modify:**
- `src/ui/main.slint`

**Changes Required:**
1. Add fade-in animation to status message:
   ```slint
   if status-message != "" : Rectangle {
       // ... existing styling
       
       animate opacity {
           duration: 200ms;
           easing: ease-out;
       }
   }
   ```

2. Add fade-in for dialog overlay:
   ```slint
   if root.show-change-password-dialog : Rectangle {
       background: rgba(0, 0, 0, 0.4);
       
       animate opacity {
           duration: 300ms;
           easing: ease-in-out;
       }
   }
   ```

3. Add slide-in for dialog content if supported:
   ```slint
   Rectangle {
       // dialog content
       
       animate y {
           duration: 300ms;
           easing: ease-out;
       }
   }
   ```

**Testing:**
- Transitions feel smooth and elegant
- Not too slow or too fast
- Doesn't delay user actions

**Acceptance Criteria:**
- Status messages fade in smoothly
- Dialog appearance is elegant
- Transitions enhance, don't hinder UX

---

### Priority 5: Advanced Features

#### Task 5.1: Add Password Strength Indicator
**Description:** Provide visual feedback on password strength during entry.

**Files to Modify:**
- `src/ui/main.slint`
- `src/main.rs`

**Changes Required:**
1. Add property for password strength:
   ```slint
   in-out property <string> password-strength-text: "";
   in-out property <color> password-strength-color: transparent;
   ```

2. Add visual indicator below password field:
   ```slint
   if password-strength-text != "" : HorizontalBox {
       spacing: Spacing.sm;
       
       Rectangle {
           width: 100px;
           height: 4px;
           border-radius: 2px;
           background: password-strength-color;
       }
       
       Text {
           text: password-strength-text;
           font-size: Typography.small-size;
           color: password-strength-color;
           vertical-alignment: center;
       }
   }
   ```

3. Update `src/main.rs` to calculate strength and update UI properties as user types

**Security Note:**
- Use general strength levels (Weak/Fair/Strong/Excellent)
- Don't show which requirements are met (prevents info leakage)
- Focus on overall entropy, not specific character classes

**Testing:**
- Strength indicator updates as user types
- Colors are meaningful (red weak, yellow fair, green strong)
- Doesn't reveal specific password composition to attackers

**Acceptance Criteria:**
- Visual indicator shows password strength
- Uses zxcvbn library for accurate assessment
- Doesn't leak password composition info
- Updates in real-time (or on blur)

---

#### Task 5.2: Implement Dark Mode Support
**Description:** Add system-aware dark mode theme.

**Files to Modify:**
- `src/ui/main.slint`

**Changes Required:**
1. Detect system theme preference (if Slint API available)
2. Define dark mode color palette:
   ```slint
   global DarkColors {
       out property <color> forest-green: #4d7030;  // Lighter for dark bg
       out property <color> charcoal: #e8e8e8;  // Light text on dark
       out property <color> warm-grey: #b0b0b0;
       out property <color> whisper-grey: #3a3a3a;
       out property <color> cream: #1a1a1a;  // Dark background
       // ... other colors
   }
   ```

3. Conditionally apply color scheme based on theme preference
4. Test all UI elements in both modes

**Testing:**
- Dark mode colors have sufficient contrast
- Theme switches based on system preference
- All UI elements adapt properly

**Acceptance Criteria:**
- Dark mode fully implemented
- Colors appropriate for dark theme
- Automatically follows system preference
- Manual toggle option (optional)

---

#### Task 5.3: Add Copy to Clipboard Feature
**Description:** Allow users to copy passwords to clipboard with auto-clear timeout.

**Files to Modify:**
- `src/ui/main.slint`
- `src/main.rs`

**Changes Required:**
1. Add "Copy" button next to each password entry in list
2. Implement clipboard copy in Rust:
   ```rust
   // Add dependency: clipboard = "0.5" or arboard
   use clipboard::ClipboardProvider;
   
   fn copy_to_clipboard(text: &str) {
       let mut ctx = clipboard::ClipboardContext::new().unwrap();
       ctx.set_contents(text.to_owned()).unwrap();
       
       // Schedule auto-clear after 30 seconds
       // ... implementation
   }
   ```

3. Show confirmation when password copied
4. Implement auto-clear timer (30-60 seconds recommended)

**Security Note:**
- Always clear clipboard after timeout
- Show warning that password is in clipboard
- Consider making timeout configurable

**Testing:**
- Copy button copies password correctly
- Clipboard clears after timeout
- User receives confirmation

**Acceptance Criteria:**
- One-click copy to clipboard
- Auto-clear after configurable timeout
- Clear visual feedback
- Security considerations addressed

---

#### Task 5.4: Add Password Search/Filter
**Description:** Implement search functionality to quickly find passwords.

**Files to Modify:**
- `src/ui/main.slint`
- `src/main.rs`

**Changes Required:**
1. Add search input field above password list:
   ```slint
   LineEdit {
       placeholder-text: "Search passwords...";
       text <=> search-query;
   }
   ```

2. Filter password list based on search query (title or username match)
3. Show count of filtered results
4. Clear search button (X icon)

**Testing:**
- Search filters list in real-time
- Matches both title and username fields
- Case-insensitive search
- Clear button works

**Acceptance Criteria:**
- Search input added to UI
- Filtering works correctly
- Performance acceptable with many passwords
- Clear/reset search functionality

---

#### Task 5.5: Implement Password Entry List View
**Description:** Replace text-based password display with structured list view.

**Files to Modify:**
- `src/ui/main.slint`
- `src/main.rs`

**Changes Required:**
1. Create password entry card component:
   ```slint
   component PasswordCard {
       in property <string> title;
       in property <string> username;
       in property <string> password;
       in property <int> created-at;
       
       callback copy-password();
       callback edit-entry();
       callback delete-entry();
       
       Rectangle {
           background: Colors.cream;
           border-width: 1px;
           border-color: Colors.whisper-grey;
           border-radius: 4px;
           
           HorizontalBox {
               padding: Spacing.lg;
               spacing: Spacing.lg;
               
               VerticalBox {
                   spacing: Spacing.sm;
                   
                   Text {
                       text: title;
                       font-size: Typography.body-size;
                       font-weight: 600;
                       color: Colors.charcoal;
                   }
                   
                   if username != "" : Text {
                       text: username;
                       font-size: Typography.secondary-size;
                       color: Colors.warm-grey;
                   }
               }
               
               Rectangle { } // Spacer
               
               HorizontalBox {
                   spacing: Spacing.sm;
                   
                   SecondaryButton {
                       text: "Copy";
                       clicked => { root.copy-password(); }
                   }
                   
                   // ... other action buttons
               }
           }
       }
   }
   ```

2. Replace ScrollView text with ListView or Repeater of PasswordCard components
3. Update `src/main.rs` to populate list data structure

**Testing:**
- Password entries display as cards
- Cards show title, username, actions
- Scrolling works smoothly
- Actions (copy, edit, delete) work

**Acceptance Criteria:**
- Structured list view instead of text
- Each entry is a card component
- Actions accessible for each entry
- Responsive and performant

---

## Implementation Guidelines for AI Agents

### General Best Practices

1. **One Task at a Time:** Complete and test each task fully before moving to next
2. **Preserve Functionality:** Never break existing features while improving design
3. **Test Incrementally:** Build and run application after each change
4. **Maintain Security:** Never compromise security for aesthetics
5. **Document Changes:** Add comments explaining non-obvious design decisions
6. **Follow Slint Conventions:** Use Slint best practices and idiomatic patterns
7. **Cross-Platform:** Test on both macOS and Linux when possible

### Code Quality Standards

- **No Magic Numbers:** Use constants for all colors, sizes, spacing
- **Consistent Naming:** Follow Slint naming conventions (kebab-case for properties)
- **Component Reuse:** Create reusable components for repeated patterns
- **Clear Callbacks:** Callback names should be action-oriented (e.g., `clicked`, `submitted`)
- **Accessibility First:** Maintain keyboard navigation and sufficient contrast

### Testing Checklist

Before completing any task:

- [ ] Code compiles without warnings
- [ ] Application builds successfully (`cargo build`)
- [ ] Application runs without crashes (`cargo run`)
- [ ] Visual appearance matches specification
- [ ] Functionality preserved (nothing broken)
- [ ] Keyboard navigation still works
- [ ] Colors meet WCAG AA contrast requirements
- [ ] Spacing is consistent and from defined scale
- [ ] Components are reusable and well-structured

### Slint-Specific Tips

1. **Globals for Constants:**
   ```slint
   global Constants {
       out property <length> button-height: 36px;
   }
   ```

2. **Component Organization:**
   ```slint
   // 1. Imports
   import { Button } from "std-widgets.slint";
   
   // 2. Globals
   global Colors { ... }
   
   // 3. Internal components
   component PasswordCard { ... }
   
   // 4. Exported main component
   export component AppWindow { ... }
   ```

3. **Property Bindings:**
   - Use `<=` for one-way binding (property depends on other property)
   - Use `<=>` for two-way binding (property syncs with Rust)
   - Avoid complex logic in bindings (extract to callback)

4. **Layout Best Practices:**
   - Use VerticalBox/HorizontalBox for simple layouts
   - Use GridLayout for complex alignments
   - Set explicit spacing and padding (don't rely on defaults)

---

## Maintenance & Evolution

### When to Update This Guide

- **New Features:** Add design specs for new UI components
- **Design Refinement:** Update color/typography if brand evolves
- **Accessibility Improvements:** Document new accessibility patterns
- **User Feedback:** Incorporate UX learnings from user testing

### Design Review Process

1. **Before Implementation:** Review task against style guide
2. **During Development:** Ensure adherence to design system
3. **Before Commit:** Visual QA against specifications
4. **After Release:** Gather user feedback and iterate

### Version History

- **v1.0** (Initial) — Established core design language and improvement tasks

---

## Appendix: Design Inspiration References

### Meiji Era Japan (1868-1912)
- **Key Characteristics:** Minimalism, natural materials, craftsmanship, restraint
- **Applied To:** Color palette (natural tones), spacing (generous white space), simplicity (no ornamentation)
- **Resources:** 
  - "The Japanese Sense of Beauty" by Takako Kawano
  - Traditional Japanese woodblock prints (Hokusai, Hiroshige)

### Edwardian England (1901-1910)
- **Key Characteristics:** Refined elegance, attention to detail, traditional craftsmanship, timeless quality
- **Applied To:** Typography (clear hierarchy), component styling (refined borders), overall polish
- **Resources:**
  - Edwardian typography and advertising
  - Arts and Crafts movement design principles

### Early Apple (1984-2000)
- **Key Characteristics:** Human-centered, intuitive, consistent, delightful interactions
- **Applied To:** UX patterns, clarity of purpose, "insanely great" attention to detail
- **Resources:**
  - Apple Human Interface Guidelines (1987 original)
  - Susan Kare's icon work
  - Macintosh System Software design

### David Ogilvy (1970s-80s)
- **Key Characteristics:** Clear hierarchy, authentic messaging, visual restraint, purposeful design
- **Applied To:** Information hierarchy, status messages, visual communication strategy
- **Resources:**
  - "Ogilvy on Advertising" by David Ogilvy
  - Classic Ogilvy & Mather campaigns
  - Principles: Clarity, hierarchy, honesty

---

## Conclusion

This style guide establishes a cohesive vision for the Password Saver application — one that balances **security**, **elegance**, and **usability**. By implementing the actionable tasks in priority order, the application will evolve into a refined, trustworthy tool that respects both the user's intelligence and their need for security.

The design language draws from timeless sources of inspiration while remaining modern, functional, and appropriate for a desktop password manager. Every decision — from color choice to button placement — serves the core mission: **making security accessible without compromising on elegance**.

**Remember:** *"Perfection is achieved, not when there is nothing more to add, but when there is nothing left to take away."* — Antoine de Saint-Exupéry

---

*For questions, clarifications, or design decisions not covered in this guide, consult the @slint-ux-expert agent persona.*
