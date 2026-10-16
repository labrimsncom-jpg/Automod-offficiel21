"""
Bot Discord — Panneau AutoMod (/automod)

Modules :
  • Règles natives Discord (création / activation / suppression)
  • Anti-Bot      : expulse automatiquement tout bot qui rejoint
  • Anti-Lien     : supprime les liens (exceptions : tickets, rôles, domaines)
  • Filtre de mots avancé : warn / timeout / kick / ban / role_remove

Requis : discord.py >= 2.6 (Components V2)
"""
from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import re
import time
import unicodedata
from datetime import timedelta
from pathlib import Path

import discord
from discord import app_commands
from discord.ext import commands, tasks

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("automod")

# ─────────────────────────── CONFIG ───────────────────────────
TOKEN = os.getenv("DISCORD_TOKEN")
DEV_GUILD_ID = os.getenv("GUILD_ID")  # optionnel : sync instantanée des commandes sur 1 serveur
DATA_FILE = Path(__file__).with_name("automod_data.json")

TICKET_KEYWORDS = ("ticket",)  # salon / catégorie contenant ce mot = "ticket" (liens autorisés)
ADMINS_BYPASS = True  # les administrateurs ne sont jamais sanctionnés par l'AutoMod
MAX_TIMEOUT = 28 * 86400  # limite Discord

SANCTIONS = {
    "warn": ("⚠️", "Avertissement"),
    "timeout": ("🔇", "Timeout (durée)"),
    "kick": ("👢", "Expulsion"),
    "ban": ("🔨", "Bannissement"),
    "role_remove": ("🎭", "Retrait d'un rôle (durée)"),
}
TRIGGER_LABELS = {
    discord.AutoModRuleTriggerType.keyword: "Mots/phrases",
    discord.AutoModRuleTriggerType.spam: "Anti-spam",
    discord.AutoModRuleTriggerType.keyword_preset: "Mots prédéfinis",
    discord.AutoModRuleTriggerType.mention_spam: "Anti-mentions",
    discord.AutoModRuleTriggerType.harmful_link: "Liens malveillants",
    discord.AutoModRuleTriggerType.member_profile: "Profils",
}
ACTION_LABELS = {
    discord.AutoModRuleActionType.block_message: "Bloquer",
    discord.AutoModRuleActionType.send_alert_message: "Alerte",
    discord.AutoModRuleActionType.timeout: "Timeout",
    discord.AutoModRuleActionType.block_member_interactions: "Bloquer interactions",
}

# ─────────────────────────── STOCKAGE ───────────────────────────
DEFAULT_GUILD = {
    "log_channel": None,
    "antibot": False,
    "antilink": {"enabled": False, "auto_warn": False, "exempt_roles": [], "allowed_domains": []},
    "wordfilter": {"enabled": False, "rules": []},
    "warns": {},
}


def _fill(dst: dict, defaults: dict) -> None:
    for key, value in defaults.items():
        if key not in dst:
            dst[key] = copy.deepcopy(value)
        elif isinstance(value, dict) and isinstance(dst[key], dict):
            _fill(dst[key], value)


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {"guilds": {}, "restores": []}
        if path.exists():
            try:
                self.data.update(json.loads(path.read_text("utf-8")))
            except json.JSONDecodeError:
                logger.warning("Fichier de données corrompu, on repart de zéro.")

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), "utf-8")
        tmp.replace(self.path)

    def guild(self, guild_id: int) -> dict:
        g = self.data["guilds"].setdefault(str(guild_id), {})
        _fill(g, DEFAULT_GUILD)
        return g


store = Store(DATA_FILE)

# ─────────────────────────── OUTILS ───────────────────────────
URL_RE = re.compile(
    r"(?i)(?:https?://|www\.)[^\s<>]+"
    r"|(?<![\w@.])(?:[a-z0-9-]+\.)+(?:com|net|org|fr|io|gg|me|co|xyz|tv|be|ch|ca|eu|de|uk|us|app|dev|info|link|ly|gl|to|cc)"
    r"(?![\w-])(?:/[^\s<>]*)?"
)


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in text if not unicodedata.combining(c))


def clean_domain(text: str) -> str:
    t = text.strip().lower()
    t = re.sub(r"^[a-z]+://", "", t)
    t = re.split(r"[/?#:]", t, maxsplit=1)[0]
    return t.removeprefix("www.")


def domain_allowed(url: str, allowed: list[str]) -> bool:
    host = clean_domain(url)
    return any(host == d or host.endswith("." + d) for d in allowed)


def parse_duration(text: str) -> int | None:
    """'30m' → 1800. Unités : s, m (défaut), h, d. Retourne None si invalide."""
    m = re.fullmatch(r"(\d+)\s*([smhdj]?)", text.strip().lower())
    if not m:
        return None
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "j": 86400}[m[2] or "m"]
    return int(m[1]) * mult


def fmt_duration(sec: int) -> str:
    if sec % 86400 == 0:
        return f"{sec // 86400}j"
    if sec % 3600 == 0:
        return f"{sec // 3600}h"
    if sec % 60 == 0:
        return f"{sec // 60}min"
    return f"{sec}s"


def resolve_role(guild: discord.Guild, text: str) -> discord.Role | None:
    m = re.search(r"\d{15,20}", text)
    if m:
        return guild.get_role(int(m.group()))
    name = text.strip().lstrip("@").lower()
    return discord.utils.find(lambda r: r.name.lower() == name, guild.roles)


def is_ticket_channel(channel) -> bool:
    names: list[str] = []
    for ch in (channel, getattr(channel, "parent", None)):
        if ch is None:
            continue
        names.append(getattr(ch, "name", "") or "")
        cat = getattr(ch, "category", None)
        if cat:
            names.append(cat.name)
    return any(k in n.lower() for n in names for k in TICKET_KEYWORDS)


def add_warn(guild_id: int, user_id: int, reason: str) -> int:
    warns = store.guild(guild_id)["warns"].setdefault(str(user_id), [])
    warns.append({"reason": reason, "at": int(time.time())})
    store.save()
    return len(warns)


async def send_log(guild: discord.Guild, title: str, description: str, color=discord.Color.orange()) -> None:
    cid = store.guild(guild.id)["log_channel"]
    channel = guild.get_channel(cid) if cid else None
    if channel is None:
        return
    embed = discord.Embed(title=title, description=description, color=color, timestamp=discord.utils.utcnow())
    try:
        await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
    except discord.HTTPException:
        pass


async def notify(channel, text: str) -> None:
    try:
        await channel.send(text, delete_after=6, allowed_mentions=discord.AllowedMentions(users=True))
    except discord.HTTPException:
        pass


def quote(text: str) -> str:
    return text[:300].replace("`", "'")


# ─────────────────────────── BOT ───────────────────────────
intents = discord.Intents.default()
intents.members = True  # privilégié : à activer dans le Developer Portal
intents.message_content = True  # privilégié : à activer dans le Developer Portal


class AutoModBot(commands.Bot):
    async def setup_hook(self) -> None:
        restore_roles.start()
        if DEV_GUILD_ID:
            guild = discord.Object(int(DEV_GUILD_ID))
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()


bot = AutoModBot(command_prefix=commands.when_mentioned, intents=intents)


@bot.event
async def on_ready():
    logger.info("Connecté en tant que %s (%s)", bot.user, bot.user.id)


# ─────────────────────────── MODÉRATION AUTO ───────────────────────────
async def apply_sanction(member: discord.Member, rule: dict, reason: str) -> str:
    sanction = rule["sanction"]
    try:
        if sanction == "warn":
            return f"avertissement n°{add_warn(member.guild.id, member.id, reason)}"
        if sanction == "timeout":
            await member.timeout(timedelta(seconds=rule["duration"]), reason=reason)
            return f"timeout {fmt_duration(rule['duration'])}"
        if sanction == "kick":
            await member.kick(reason=reason)
            return "expulsion"
        if sanction == "ban":
            await member.ban(reason=reason, delete_message_seconds=0)
            return "bannissement"
        if sanction == "role_remove":
            role = member.guild.get_role(rule["role_id"] or 0)
            if role is None or role not in member.roles:
                return "retrait de rôle ignoré (rôle absent)"
            await member.remove_roles(role, reason=reason)
            if rule["duration"]:
                store.data["restores"].append(
                    {
                        "guild": member.guild.id,
                        "user": member.id,
                        "role": role.id,
                        "at": time.time() + rule["duration"],
                    }
                )
                store.save()
                return f"retrait du rôle {role.name} ({fmt_duration(rule['duration'])})"
            return f"retrait du rôle {role.name} (définitif)"
    except discord.HTTPException:
        return f"⚠️ {sanction} impossible (permissions ou hiérarchie des rôles)"
    return "aucune"


async def handle_links(message: discord.Message, member: discord.Member, cfg: dict) -> bool:
    al = cfg["antilink"]
    if is_ticket_channel(message.channel):
        return False
    if any(r.id in al["exempt_roles"] for r in member.roles):
        return False
    bad = [u for u in URL_RE.findall(message.content) if not domain_allowed(u, al["allowed_domains"])]
    if not bad:
        return False

    try:
        await message.delete()
    except discord.HTTPException:
        pass

    result = "message supprimé"
    if al["auto_warn"]:
        n = add_warn(message.guild.id, member.id, "Lien non autorisé")
        result += f" + avertissement n°{n}"
        await notify(message.channel, f"🔗 {member.mention}, les liens sont interdits ici. **Avertissement n°{n}**.")
    else:
        await notify(message.channel, f"🔗 {member.mention}, les liens sont interdits ici.")

    await send_log(
        message.guild,
        "🔗 Anti-Lien",
        f"**Membre :** {member.mention} (`{member.id}`)\n**Salon :** {message.channel.mention}\n"
        f"**Action :** {result}\n**Contenu :** `{quote(message.content)}`",
    )
    return True


async def handle_words(message: discord.Message, member: discord.Member, cfg: dict) -> None:
    content = normalize(message.content)
    hit = None
    for rule in cfg["wordfilter"]["rules"]:
        word = normalize(rule["word"]).strip()
        if word and re.search(rf"(?<!\w){re.escape(word)}(?!\w)", content):
            hit = rule
            break
    if hit is None:
        return

    try:
        await message.delete()
    except discord.HTTPException:
        pass

    result = await apply_sanction(member, hit, f"Filtre de mots : « {hit['word']} »")
    await notify(message.channel, f"🚫 {member.mention}, ce message contenait un mot interdit. ({result})")
    await send_log(
        message.guild,
        "🚫 Filtre de mots",
        f"**Membre :** {member.mention} (`{member.id}`)\n**Salon :** {message.channel.mention}\n"
        f"**Mot :** `{quote(hit['word'])}`\n**Sanction :** {result}\n**Contenu :** `{quote(message.content)}`",
        discord.Color.red(),
    )


async def moderate(message: discord.Message) -> None:
    if message.guild is None or message.author.bot or not isinstance(message.author, discord.Member):
        return
    member = message.author
    if ADMINS_BYPASS and member.guild_permissions.administrator:
        return
    cfg = store.guild(message.guild.id)
    if cfg["antilink"]["enabled"] and await handle_links(message, member, cfg):
        return
    if cfg["wordfilter"]["enabled"]:
        await handle_words(message, member, cfg)


@bot.listen("on_message")
async def _on_message(message: discord.Message):
    await moderate(message)


@bot.listen("on_message_edit")
async def _on_message_edit(before: discord.Message, after: discord.Message):
    if before.content != after.content:
        await moderate(after)


@bot.listen("on_member_join")
async def _antibot(member: discord.Member):
    if not member.bot or member.id == bot.user.id:
        return
    if not store.guild(member.guild.id)["antibot"]:
        return

    adder = None
    try:
        await asyncio.sleep(1.5)  # le journal d'audit a un léger délai
        async for entry in member.guild.audit_logs(limit=10, action=discord.AuditLogAction.bot_add):
            if entry.target and entry.target.id == member.id:
                adder = entry.user
                break
    except discord.HTTPException:
        pass

    try:
        await member.kick(reason="Anti-Bot : ajout de bot interdit")
        status = "✅ expulsé"
    except discord.HTTPException:
        status = "❌ expulsion impossible (permissions ou hiérarchie)"

    await send_log(
        member.guild,
        "🤖 Anti-Bot",
        f"**Bot :** {member.mention} (`{member.id}`)\n"
        f"**Ajouté par :** {adder.mention if adder else 'inconnu'}\n**Résultat :** {status}",
        discord.Color.red(),
    )


@tasks.loop(seconds=30)
async def restore_roles():
    now = time.time()
    due = [r for r in store.data["restores"] if r["at"] <= now]
    if not due:
        return
    for r in due:
        guild = bot.get_guild(r["guild"])
        member = guild.get_member(r["user"]) if guild else None
        role = guild.get_role(r["role"]) if guild else None
        if member and role:
            try:
                await member.add_roles(role, reason="Fin du retrait de rôle (AutoMod)")
            except discord.HTTPException:
                logger.warning("Impossible de restaurer le rôle %s à %s", r["role"], r["user"])
        store.data["restores"].remove(r)
    store.save()


@restore_roles.before_loop
async def _before_restore():
    await bot.wait_until_ready()


# ─────────────────────────── PANNEAU : BASES ───────────────────────────
async def admin_check(interaction: discord.Interaction) -> bool:
    perms = getattr(interaction.user, "guild_permissions", None)
    if perms and perms.manage_guild:
        return True
    await interaction.response.send_message(
        "❌ Réservé aux membres ayant la permission **Gérer le serveur**.", ephemeral=True
    )
    return False


class AdminLayout(discord.ui.LayoutView):
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return await admin_check(interaction)


class AdminView(discord.ui.View):
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return await admin_check(interaction)


async def refresh(panel: discord.Message, guild: discord.Guild) -> None:
    """Réaffiche le panneau principal avec l'état à jour."""
    try:
        await panel.edit(view=await build_panel(guild))
    except discord.HTTPException:
        logger.exception("Impossible de rafraîchir le panneau")


def make_toggle(section: str | None, key: str):
    async def callback(interaction: discord.Interaction):
        g = store.guild(interaction.guild_id)
        target = g if section is None else g[section]
        target[key] = not target[key]
        store.save()
        await interaction.response.defer()
        await refresh(interaction.message, interaction.guild)

    return callback


def button(label, style, callback, *, emoji=None, disabled=False) -> discord.ui.Button:
    b = discord.ui.Button(label=label, style=style, emoji=emoji, disabled=disabled)
    b.callback = callback
    return b


# ─────────────────────────── PANNEAU : RÈGLES NATIVES ───────────────────────────
def describe_rule(rule: discord.AutoModRule) -> str:
    trig = TRIGGER_LABELS.get(rule.trigger.type, rule.trigger.type.name)
    acts = ", ".join(ACTION_LABELS.get(a.type, a.type.name) for a in rule.actions) or "—"
    off = "" if rule.enabled else " *(désactivée)*"
    return f"**{discord.utils.escape_markdown(rule.name)}** — {trig} → {acts}{off}"


async def create_native_rule(guild, name, trigger, by) -> None:
    await guild.create_automod_rule(
        name=name,
        event_type=discord.AutoModRuleEventType.message_send,
        trigger=trigger,
        actions=[discord.AutoModRuleAction(type=discord.AutoModRuleActionType.block_message)],
        enabled=True,
        reason=f"Panneau AutoMod — {by}",
    )


class NativeKeywordsModal(discord.ui.Modal):
    def __init__(self, panel: discord.Message):
        super().__init__(title="Règle native : mots interdits")
        self.panel = panel
        self.words = discord.ui.TextInput(
            label="Mots/phrases (un par ligne ou séparés par ,)",
            style=discord.TextStyle.paragraph,
            placeholder="mot1\nmot2\nune phrase interdite\n*joker*",
            max_length=2000,
        )
        self.add_item(self.words)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer()
        words = [w.strip()[:60] for w in re.split(r"[\n,]+", self.words.value) if w.strip()]
        try:
            await create_native_rule(
                interaction.guild,
                "Mots interdits",
                discord.AutoModTrigger(type=discord.AutoModRuleTriggerType.keyword, keyword_filter=words),
                interaction.user,
            )
        except discord.HTTPException as e:
            await interaction.followup.send(f"❌ Impossible de créer la règle : {e.text}", ephemeral=True)
        await refresh(self.panel, interaction.guild)


class RulePickerView(AdminView):
    def __init__(self, action: str, rules: list[discord.AutoModRule], panel: discord.Message):
        super().__init__(timeout=120)
        self.action, self.panel = action, panel
        self.select = discord.ui.Select(
            placeholder="Choisir une règle...",
            options=[
                discord.SelectOption(
                    label=r.name[:100],
                    value=str(r.id),
                    description=TRIGGER_LABELS.get(r.trigger.type, "Règle") + (" • active" if r.enabled else " • désactivée"),
                )
                for r in rules[:25]
            ],
        )
        self.select.callback = self.picked
        self.add_item(self.select)

    async def picked(self, interaction: discord.Interaction):
        guild = interaction.guild
        try:
            rule = await guild.fetch_automod_rule(int(self.select.values[0]))
            if self.action == "delete":
                await rule.delete(reason=f"Panneau AutoMod — {interaction.user}")
                text = f"🗑️ Règle **{rule.name}** supprimée."
            else:
                new = await rule.edit(enabled=not rule.enabled, reason=f"Panneau AutoMod — {interaction.user}")
                text = f"🔁 Règle **{new.name}** : {'activée' if new.enabled else 'désactivée'}."
        except discord.HTTPException as e:
            text = f"❌ {e.text}"
        await interaction.response.edit_message(content=text, view=None)
        await refresh(self.panel, guild)


async def on_native_action(interaction: discord.Interaction, action: str) -> None:
    guild, panel = interaction.guild, interaction.message

    if action == "create_keyword":
        return await interaction.response.send_modal(NativeKeywordsModal(panel))

    if action in ("create_spam", "create_mention"):
        await interaction.response.defer()
        if action == "create_spam":
            name = "Anti-Spam"
            trigger = discord.AutoModTrigger(type=discord.AutoModRuleTriggerType.spam)
        else:
            name = "Anti-Mention-Spam"
            trigger = discord.AutoModTrigger(type=discord.AutoModRuleTriggerType.mention_spam, mention_limit=5)
        try:
            await create_native_rule(guild, name, trigger, interaction.user)
        except discord.HTTPException as e:
            await interaction.followup.send(
                f"❌ Impossible de créer la règle (déjà existante ? limite atteinte ?) : {e.text}", ephemeral=True
            )
        return await refresh(panel, guild)

    # toggle / delete
    try:
        rules = await guild.fetch_automod_rules()
    except discord.HTTPException as e:
        return await interaction.response.send_message(f"❌ {e.text}", ephemeral=True)
    if not rules:
        return await interaction.response.send_message("Aucune règle native à gérer.", ephemeral=True)
    verb = "supprimer" if action == "delete" else "activer/désactiver"
    await interaction.response.send_message(
        f"Quelle règle veux-tu {verb} ?", view=RulePickerView(action, rules, panel), ephemeral=True
    )


# ─────────────────────────── PANNEAU : ANTI-LIEN ───────────────────────────
class DomainsModal(discord.ui.Modal):
    def __init__(self, panel: discord.Message, current: list[str]):
        super().__init__(title="Domaines autorisés")
        self.panel = panel
        self.domains = discord.ui.TextInput(
            label="Un domaine par ligne",
            style=discord.TextStyle.paragraph,
            required=False,
            max_length=1000,
            placeholder="youtube.com\ntenor.com",
            default="\n".join(current) or None,
        )
        self.add_item(self.domains)

    async def on_submit(self, interaction: discord.Interaction):
        items: list[str] = []
        for line in re.split(r"[\n,; ]+", self.domains.value or ""):
            d = clean_domain(line)
            if d and d not in items:
                items.append(d)
        store.guild(interaction.guild_id)["antilink"]["allowed_domains"] = items[:50]
        store.save()
        await interaction.response.send_message(f"✅ {len(items[:50])} domaine(s) autorisé(s).", ephemeral=True)
        await refresh(self.panel, interaction.guild)


class LinkConfigView(AdminView):
    def __init__(self, panel: discord.Message, guild: discord.Guild):
        super().__init__(timeout=300)
        self.panel = panel
        al = store.guild(guild.id)["antilink"]
        roles = [r for rid in al["exempt_roles"] if (r := guild.get_role(rid))]
        self.roles = discord.ui.RoleSelect(
            placeholder="Rôles exemptés (aucun)", min_values=0, max_values=25, default_values=roles, row=0
        )
        self.roles.callback = self.on_roles
        self.add_item(self.roles)

    async def on_roles(self, interaction: discord.Interaction):
        store.guild(interaction.guild_id)["antilink"]["exempt_roles"] = [r.id for r in self.roles.values]
        store.save()
        await interaction.response.defer()
        await refresh(self.panel, interaction.guild)

    @discord.ui.button(label="Domaines autorisés", emoji="🌐", style=discord.ButtonStyle.primary, row=1)
    async def domains(self, interaction: discord.Interaction, _: discord.ui.Button):
        current = store.guild(interaction.guild_id)["antilink"]["allowed_domains"]
        await interaction.response.send_modal(DomainsModal(self.panel, current))


# ─────────────────────────── PANNEAU : FILTRE DE MOTS ───────────────────────────
class WordModal(discord.ui.Modal):
    def __init__(self, panel: discord.Message, sanction: str):
        super().__init__(title=f"Mot interdit → {sanction}")
        self.panel, self.sanction = panel, sanction
        self.word = discord.ui.TextInput(label="Mot ou phrase interdit(e)", max_length=100)
        self.add_item(self.word)
        self.duration = self.role = None
        if sanction in ("timeout", "role_remove"):
            hint = "Durée (30m, 2h, 1d)" if sanction == "timeout" else "Durée (30m, 2h, 1d — 0 = définitif)"
            self.duration = discord.ui.TextInput(label=hint, default="10m", max_length=10)
            self.add_item(self.duration)
        if sanction == "role_remove":
            self.role = discord.ui.TextInput(label="Rôle à retirer (ID ou nom)", max_length=100)
            self.add_item(self.role)

    async def on_submit(self, interaction: discord.Interaction):
        word = self.word.value.strip()
        duration, role_id = 0, None

        if self.duration is not None:
            parsed = parse_duration(self.duration.value)
            if parsed is None:
                return await interaction.response.send_message("❌ Durée invalide (ex : `30m`, `2h`, `1d`).", ephemeral=True)
            if self.sanction == "timeout" and not 0 < parsed <= MAX_TIMEOUT:
                return await interaction.response.send_message("❌ Le timeout doit durer entre 1s et 28j.", ephemeral=True)
            duration = parsed
        if self.role is not None:
            role = resolve_role(interaction.guild, self.role.value)
            if role is None:
                return await interaction.response.send_message("❌ Rôle introuvable.", ephemeral=True)
            role_id = role.id

        wf = store.guild(interaction.guild_id)["wordfilter"]
        key = normalize(word)
        wf["rules"] = [r for r in wf["rules"] if normalize(r["word"]) != key]
        wf["rules"].append({"word": word, "sanction": self.sanction, "duration": duration, "role_id": role_id})
        store.save()

        await interaction.response.edit_message(content=f"✅ `{quote(word)}` ajouté → `{self.sanction}`", view=None)
        await refresh(self.panel, interaction.guild)


class SanctionPickView(AdminView):
    def __init__(self, panel: discord.Message):
        super().__init__(timeout=120)
        self.panel = panel
        self.select = discord.ui.Select(
            placeholder="Sanction à appliquer...",
            options=[
                discord.SelectOption(label=label, value=key, emoji=emoji, description=key)
                for key, (emoji, label) in SANCTIONS.items()
            ],
        )
        self.select.callback = self.picked
        self.add_item(self.select)

    async def picked(self, interaction: discord.Interaction):
        await interaction.response.send_modal(WordModal(self.panel, self.select.values[0]))


class RemoveWordView(AdminView):
    def __init__(self, panel: discord.Message, rules: list[dict]):
        super().__init__(timeout=120)
        self.panel = panel
        self.select = discord.ui.Select(
            placeholder="Mot à retirer...",
            options=[
                discord.SelectOption(label=r["word"][:100], value=r["word"][:100], description=r["sanction"])
                for r in rules[:25]
            ],
        )
        self.select.callback = self.picked
        self.add_item(self.select)

    async def picked(self, interaction: discord.Interaction):
        chosen = self.select.values[0]
        wf = store.guild(interaction.guild_id)["wordfilter"]
        wf["rules"] = [r for r in wf["rules"] if r["word"][:100] != chosen]
        store.save()
        await interaction.response.edit_message(content=f"🗑️ `{quote(chosen)}` retiré.", view=None)
        await refresh(self.panel, interaction.guild)


def describe_word(r: dict) -> str:
    emoji, _ = SANCTIONS[r["sanction"]]
    word = r["word"].replace("`", "'")
    extra = ""
    if r["sanction"] in ("timeout", "role_remove"):
        extra = f" ({fmt_duration(r['duration'])})" if r["duration"] else " (définitif)"
    if r["sanction"] == "role_remove" and r.get("role_id"):
        extra += f" <@&{r['role_id']}>"
    return f"`{word}` → {emoji} `{r['sanction']}`{extra}"


# ─────────────────────────── PANNEAU PRINCIPAL ───────────────────────────
async def build_panel(guild: discord.Guild) -> AdminLayout:
    cfg = store.guild(guild.id)
    al, wf = cfg["antilink"], cfg["wordfilter"]
    on_off = lambda v: "**Activé**" if v else "**Désactivé**"  # noqa: E731

    # ── Règles natives
    try:
        rules = await guild.fetch_automod_rules()
    except discord.HTTPException:
        rules = None

    native = (
        "## 🤖 AutoMod Discord — Règles natives\n"
        "Ces règles sont gérées **directement par Discord** et s'appliquent même sans votre bot en ligne.\n\n"
    )
    if rules is None:
        native += "⚠️ Je n'ai pas la permission **Gérer le serveur** pour lire les règles."
    elif not rules:
        native += "**0 règle(s) :**\n*Aucune règle native configurée.*"
    else:
        native += f"**{len(rules)} règle(s) :**\n" + "\n".join(describe_rule(r) for r in rules[:8])
        if len(rules) > 8:
            native += f"\n*… et {len(rules) - 8} autre(s)*"

    select = discord.ui.Select(
        placeholder="Choisir une action...",
        options=[
            discord.SelectOption(label="Créer : Mots interdits", value="create_keyword", emoji="📝",
                                 description="Règle native avec liste de mots/phrases"),
            discord.SelectOption(label="Créer : Anti-Spam", value="create_spam", emoji="🚫",
                                 description="Bloque le spam détecté par Discord"),
            discord.SelectOption(label="Créer : Anti-Mention-Spam", value="create_mention", emoji="📣",
                                 description="Bloque les messages avec 5 mentions ou plus"),
            discord.SelectOption(label="Activer / désactiver une règle", value="toggle", emoji="🔁"),
            discord.SelectOption(label="Supprimer une règle", value="delete", emoji="🗑️"),
        ],
    )

    async def native_cb(interaction: discord.Interaction):
        await on_native_action(interaction, select.values[0])

    select.callback = native_cb

    # ── Anti-Bot
    antibot = (
        "## 🤖 Anti-Bot — Protection bot-side\n"
        "Empêche les membres d'ajouter des bots au serveur.\n"
        "Tout bot qui rejoint sera **expulsé automatiquement** et l'action sera loggée.\n\n"
        f"Statut actuel : {on_off(cfg['antibot'])}"
    )

    # ── Anti-Lien
    roles = " ".join(f"<@&{rid}>" for rid in al["exempt_roles"][:10]) or "*aucun*"
    domains = ", ".join(f"`{d}`" for d in al["allowed_domains"][:15]) or "*aucun*"
    antilink = (
        "## 🔗 Anti-Lien\n"
        "Supprime automatiquement les messages contenant des liens.\n"
        "**Exception automatique** : les liens dans les **tickets** sont toujours autorisés.\n\n"
        f"Statut : {on_off(al['enabled'])}\n"
        f"Warn automatique : {'Oui' if al['auto_warn'] else 'Non'}\n"
        f"Rôles exemptés : {roles}\n"
        f"Domaines autorisés : {domains}"
    )

    async def configure_links(interaction: discord.Interaction):
        await interaction.response.send_message(
            "**Anti-Lien — configuration**\nChoisis les rôles exemptés, ou gère les domaines autorisés :",
            view=LinkConfigView(interaction.message, interaction.guild),
            ephemeral=True,
        )

    # ── Filtre de mots
    words = wf["rules"]
    shown = "\n".join(describe_word(r) for r in words[:10]) if words else "*Aucun mot configuré.*"
    if len(words) > 10:
        shown += f"\n*… et {len(words) - 10} autre(s)*"
    wordfilter = (
        "## 🛡️ Filtre de mots avancé\n"
        "Supprime automatiquement les messages contenant un mot interdit et applique la sanction associée\n"
        "(`warn` / `timeout` / `kick` / `ban` / `role_remove`, avec durée pour timeout et role_remove).\n\n"
        f"Statut : {on_off(wf['enabled'])}\n\n"
        f"**Règles ({len(words)}) :**\n{shown}"
    )

    async def add_word(interaction: discord.Interaction):
        await interaction.response.send_message(
            "Quelle sanction appliquer pour ce mot ?", view=SanctionPickView(interaction.message), ephemeral=True
        )

    async def remove_word(interaction: discord.Interaction):
        rules_ = store.guild(interaction.guild_id)["wordfilter"]["rules"]
        if not rules_:
            return await interaction.response.send_message("Aucun mot à retirer.", ephemeral=True)
        await interaction.response.send_message(
            "Quel mot retirer ?", view=RemoveWordView(interaction.message, rules_), ephemeral=True
        )

    async def clear_words(interaction: discord.Interaction):
        store.guild(interaction.guild_id)["wordfilter"]["rules"] = []
        store.save()
        await interaction.response.defer()
        await refresh(interaction.message, interaction.guild)

    S = discord.ButtonStyle
    container = discord.ui.Container(
        discord.ui.TextDisplay(native),
        discord.ui.Separator(),
        discord.ui.ActionRow(select),
        discord.ui.Separator(),
        discord.ui.TextDisplay(antibot),
        discord.ui.ActionRow(
            button(
                "Désactiver l'Anti-Bot" if cfg["antibot"] else "Activer l'Anti-Bot",
                S.danger if cfg["antibot"] else S.success,
                make_toggle(None, "antibot"),
                emoji="🔘",
            )
        ),
        discord.ui.Separator(),
        discord.ui.TextDisplay(antilink),
        discord.ui.ActionRow(
            button(
                "Désactiver l'Anti-Lien" if al["enabled"] else "Activer l'Anti-Lien",
                S.danger if al["enabled"] else S.success,
                make_toggle("antilink", "enabled"),
                emoji="🔘",
            ),
            button(
                f"Warn : {'ON' if al['auto_warn'] else 'OFF'}",
                S.success if al["auto_warn"] else S.secondary,
                make_toggle("antilink", "auto_warn"),
            ),
            button("Configurer", S.secondary, configure_links),
        ),
        discord.ui.Separator(),
        discord.ui.TextDisplay(wordfilter),
        discord.ui.ActionRow(
            button(
                "Désactiver le filtre" if wf["enabled"] else "Activer le filtre",
                S.danger if wf["enabled"] else S.success,
                make_toggle("wordfilter", "enabled"),
            ),
            button("Ajouter un mot", S.primary, add_word),
            button("Retirer un mot", S.secondary, remove_word, disabled=not words),
            button("Vider la liste", S.danger, clear_words, disabled=not words),
        ),
    )

    view = AdminLayout(timeout=900)
    view.add_item(container)
    return view


# ─────────────────────────── COMMANDES ───────────────────────────
@bot.tree.command(name="automod", description="Ouvre le panneau de configuration AutoMod")
@app_commands.guild_only()
@app_commands.default_permissions(manage_guild=True)
async def automod(interaction: discord.Interaction):
    if not await admin_check(interaction):
        return
    await interaction.response.defer()
    await interaction.followup.send(view=await build_panel(interaction.guild), allowed_mentions=discord.AllowedMentions.none())


@bot.tree.command(name="automod_logs", description="Définit le salon où sont envoyés les logs AutoMod")
@app_commands.guild_only()
@app_commands.default_permissions(manage_guild=True)
@app_commands.describe(salon="Salon de logs")
async def automod_logs(interaction: discord.Interaction, salon: discord.TextChannel):
    store.guild(interaction.guild_id)["log_channel"] = salon.id
    store.save()
    await interaction.response.send_message(f"✅ Logs AutoMod envoyés dans {salon.mention}.", ephemeral=True)


@bot.tree.command(name="warns", description="Affiche les avertissements d'un membre")
@app_commands.guild_only()
@app_commands.default_permissions(moderate_members=True)
@app_commands.describe(membre="Membre à consulter")
async def warns_cmd(interaction: discord.Interaction, membre: discord.Member):
    warns = store.guild(interaction.guild_id)["warns"].get(str(membre.id), [])
    if not warns:
        return await interaction.response.send_message(f"{membre.mention} n'a aucun avertissement.", ephemeral=True)
    last = warns[-15:]
    start = len(warns) - len(last) + 1
    lines = [f"`{i}.` <t:{w['at']}:d> — {w['reason']}" for i, w in enumerate(last, start)]
    await interaction.response.send_message(
        f"**{len(warns)} avertissement(s) pour {membre.mention} :**\n" + "\n".join(lines),
        ephemeral=True,
        allowed_mentions=discord.AllowedMentions.none(),
    )


@bot.tree.command(name="clearwarns", description="Efface les avertissements d'un membre")
@app_commands.guild_only()
@app_commands.default_permissions(moderate_members=True)
@app_commands.describe(membre="Membre concerné")
async def clearwarns_cmd(interaction: discord.Interaction, membre: discord.Member):
    store.guild(interaction.guild_id)["warns"].pop(str(membre.id), None)
    store.save()
    await interaction.response.send_message(
        f"✅ Avertissements de {membre.mention} effacés.", ephemeral=True, allowed_mentions=discord.AllowedMentions.none()
    )


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Définis la variable d'environnement DISCORD_TOKEN (ou un fichier .env).")
    bot.run(TOKEN)
