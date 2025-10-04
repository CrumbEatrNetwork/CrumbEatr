// @ts-ignore
import template from "./style.css";
import { currentRealm } from "./common";
import { Theme } from "./types";

var shade = function (color: string, percent: number) {
    var num = parseInt(color.replace("#", ""), 16),
        amt = Math.round(2.55 * percent),
        R = (num >> 16) + amt,
        B = ((num >> 8) & 0x00ff) + amt,
        G = (num & 0x0000ff) + amt;
    return (
        0x1000000 +
        (R < 255 ? (R < 1 ? 0 : R) : 255) * 0x10000 +
        (B < 255 ? (B < 1 ? 0 : B) : 255) * 0x100 +
        (G < 255 ? (G < 1 ? 0 : G) : 255)
    )
        .toString(16)
        .slice(1);
};

export const getTheme = (name: string) => themes[name];

const themes: { [name: string]: Theme } = {
    black: {
        text: "#EDF0EF",
        background: "#000000",
        code: "White",
        clickable: "#FF6B47",
        accent: "#75FBA5",
        light_factor: 5,
        dark_factor: 5,
    },
    calm: {
        text: "#EDF0EF",
        background: "#343541",
        code: "White",
        clickable: "#FF6B47",
        accent: "#75FBA5",
    },
    classic: {
        text: "#EDF0EF",
        background: "#1c3239",
        code: "White",
        clickable: "#FF6B47",
        accent: "#75FBA5",
    },
    dark: {
        text: "#EDF0EF",
        background: "#1e1e23",
        code: "White",
        clickable: "#FF6B47",
        accent: "#75FBA5",
    },
    light: {
        text: "#101010",
        background: "#EAEAEA",
        code: "black",
        clickable: "#E55100",
        accent: "MediumSeaGreen",
    },
    midnight: {
        text: "#EDF0EF",
        background: "#111d2b",
        code: "White",
        clickable: "#FF6B47",
        accent: "#75FBA5",
    },
};

const applyTheme = (palette: Theme) => {
    const effPalette: Theme = palette ? palette : themes["black"];
    effPalette.light_background =
        "#" + shade(effPalette.background, effPalette.light_factor || 3);
    effPalette.dark_background =
        "#" + shade(effPalette.background, effPalette.dark_factor || -5);
    effPalette.frame = "#" + shade(effPalette.background, 10);
    effPalette.visited_clickable = "#" + shade(effPalette.clickable, -20);
    effPalette.frame = effPalette.frame || effPalette.dark_background;
    const styleNode = document.getElementById("style");
    if (!styleNode) return;
    styleNode.innerText = Object.keys(effPalette).reduce(
        (acc, color) => acc.replaceAll(`$${color}`, effPalette[color]),
        template,
    );
    const element = document.getElementsByName("theme-color")[0];
    if (element) element.setAttribute("content", effPalette.background);
};

export const setTheme = (name: string) => applyTheme(getTheme(name));

// If no realm is selected, set styling once.
export const setUI = (force?: boolean) => {
    if (!force && (currentRealm() || window.uiInitialized)) return;
    setTheme(window.user?.settings.theme);
    window.uiInitialized = true;
};

export const setRealmUI = (realm: string) => {
    window.realm = realm;
    if (window.user && window.user.settings.overrideRealmColors == "true")
        return;
    window.api.query("realms", [realm]).then((result: any) => {
        let realm = result[0];
        let realmTheme = realm.theme;
        if (realmTheme) applyTheme(JSON.parse(realmTheme));
        else setUI(true);
    });
};
