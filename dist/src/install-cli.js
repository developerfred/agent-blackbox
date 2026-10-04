'use strict';
// Install/uninstall without starting the daemon (used by tests and scripts).
const { install, uninstall } = require('./install');
const [cmd, ...args] = process.argv.slice(2);
const quiet = () => { };
if (cmd === 'install')
    install({ raw: args.includes('--raw'), prompts: args.includes('--prompts'), force: args.includes('--force'), log: quiet });
else if (cmd === 'uninstall')
    uninstall({ log: quiet });
else {
    console.error('usage: install-cli.js install|uninstall');
    process.exit(1);
}
