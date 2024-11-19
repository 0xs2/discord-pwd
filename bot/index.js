const { Client, GatewayIntentBits, REST, Routes, PermissionFlagsBits } = require('discord.js');
const fs = require('fs');
const crypto = require('crypto');

const path = './pwdProtected.json';

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

if (!fs.existsSync(path)) {
    fs.writeFileSync(path, JSON.stringify({}));
}

function hashPassphrase(passphrase) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto
        .pbkdf2Sync(passphrase, salt, 1000, 64, 'sha512')
        .toString('hex');
    return { salt, hash };
}

function verifyPassphrase(passphrase, salt, hash) {
    const hashVerify = crypto
        .pbkdf2Sync(passphrase, salt, 1000, 64, 'sha512')
        .toString('hex');
    return hash === hashVerify;
}

const commands = [
    {
        name: 'pwd-list',
        description: 'list all pwd-protected channels.',
    },
    {
        name: 'pwd-new',
        description: 'create a pwd-protected channel.',
        options: [
            {
                name: 'channelname',
                description: 'The name of the channel to protect.',
                type: 3,
                required: true,
            },
            {
                name: 'passphrase',
                description: 'The passphrase for the channel.',
                type: 3,
                required: true,
            },
        ],
    },
    {
        name: 'pwd-unlock',
        description: 'unlock a password-protected channel for 30 minutes.',
        options: [
            {
                name: 'channelname',
                description: 'the name of the channel to unlock.',
                type: 3,
                required: true,
            },
            {
                name: 'passphrase',
                description: 'The passphrase to unlock the channel.',
                type: 3,
                required: true,
            },
        ],
    },
];

const rest = new REST({ version: '10' }).setToken(process.env.TOKEN);

(async () => {
    try {
        await rest.put(Routes.applicationGuildCommands(process.env.CLIENT_ID, process.env.GUILD_ID), {
            body: commands,
        });
    } catch (error) {
        console.error(error);
    }
})();

client.on('ready', () => {
    console.log(`Logged in as ${client.user.tag}!`);
});

client.on('interactionCreate', async (interaction) => {
    if (!interaction.isChatInputCommand()) return;

    const { commandName, options } = interaction;

    const data = JSON.parse(fs.readFileSync(path, 'utf8'));

    if (commandName === 'pwd-list') {
        const channels = Object.keys(data).join(', ') || 'None';
        await interaction.reply(`pwd-protected channels: ${channels}`);
    } else if (commandName === 'pwd-new') {
        const channelName = options.getString('channelname');
        const passphrase = options.getString('passphrase');
        const channel = interaction.guild.channels.cache.find(
            (ch) => ch.name === channelName
        );

        if (!channel) {
            return interaction.reply(`channel "${channelName}" not found.`);
        }

        const { salt, hash } = hashPassphrase(passphrase);
        data[channel.id] = { salt, hash };
        fs.writeFileSync(path, JSON.stringify(data, null, 2));

        await channel.permissionOverwrites.edit(interaction.guild.roles.everyone, {
            ViewChannel: false,
        });

        await interaction.reply(
            `channel "${channelName}" is now pwd-protected.`
        );
    } else if (commandName === 'pwd-unlock') {
        const channelName = options.getString('channelname');
        const passphrase = options.getString('passphrase');
        const channel = interaction.guild.channels.cache.find(
            (ch) => ch.name === channelName
        );

        if (!channel) {
            return interaction.reply(`Channel "${channelName}" not found.`);
        }

        const channelData = data[channel.id];
        if (!channelData) {
            return interaction.reply(`"${channelName}" is not password-protected.`);
        }

        const { salt, hash } = channelData;

        if (!verifyPassphrase(passphrase, salt, hash)) {
            return interaction.reply('Invalid passphrase.');
        }

        await channel.permissionOverwrites.edit(interaction.user, {
            ViewChannel: true,
        });

        await interaction.reply(
            `you have unlocked "${channelName}". access will be revoked in 30 minutes.`
        );

        setTimeout(async () => {
            await channel.permissionOverwrites.delete(interaction.user);
        }, 30 * 60 * 1000);
    }
});

client.login(process.env.TOKEN);
