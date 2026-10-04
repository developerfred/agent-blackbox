"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// Install/uninstall without starting the daemon (used by tests and scripts).
const install_1 = require("./install");
const [cmd, ...args] = process.argv.slice(2);
const quiet = () => { };
if (cmd === 'install')
    (0, install_1.install)({ raw: args.includes('--raw'), prompts: args.includes('--prompts'), force: args.includes('--force'), log: quiet });
else if (cmd === 'uninstall')
    (0, install_1.uninstall)({ log: quiet });
else {
    console.error('usage: install-cli.js install|uninstall');
    process.exit(1);
}
