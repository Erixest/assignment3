// Disable htmx's eval/Function() usage to comply with strict script-src CSP.
// hx-on:* and JavaScript expressions in htmx attributes are not used in this app.
htmx.config.allowEval = false;
