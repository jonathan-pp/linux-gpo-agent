#!/usr/bin/env python3
"""Génère LinuxGPO.admx, fr-FR/LinuxGPO.adml, en-US/LinuxGPO.adml et definitions.json depuis definitions.py.

    python3 admx/generer.py
"""
import json
import os
import sys
from xml.sax.saxutils import escape, quoteattr

ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ICI)
from definitions import CATEGORIES, PARAMETRES  # noqa: E402


def _element(el, cle):
    t, i, v = el['type'], el['id'], el['valeur']
    k = f' key={quoteattr(el["cle"])}' if el.get('cle') else ''
    if t == 'nombre':
        return f'<decimal id="{i}"{k} valueName="{v}" minValue="{el.get("min", 0)}" maxValue="{el.get("max", 999999)}"/>'
    if t == 'texte':
        return f'<text id="{i}"{k} valueName="{v}"/>'
    if t == 'multi':
        return f'<multiText id="{i}"{k} valueName="{v}"/>'
    if t == 'case':
        return (f'<boolean id="{i}"{k} valueName="{v}"><trueValue><decimal value="1"/></trueValue>'
                '<falseValue><decimal value="0"/></falseValue></boolean>')
    if t == 'choix':
        items = ''.join(f'<item displayName="$(string.{i}_{n})"><value><decimal value="{n}"/></value></item>' for n, _, _ in el['choix'])
        return f'<enum id="{i}"{k} valueName="{v}">{items}</enum>'
    if t == 'liste':
        return f'<list id="{i}" key={quoteattr(el.get("cle") or cle)} valuePrefix=""/>'
    if t == 'paires':
        return f'<list id="{i}" key={quoteattr(el.get("cle") or cle)} explicitValue="true"/>'
    raise ValueError(t)


def admx() -> str:
    cats = ''.join(f'    <category name="{c}" displayName="$(string.cat_{c})">'
                   + (f'<parentCategory ref="{parent}"/>' if parent else '') + '</category>\n' for c, parent, _, _ in CATEGORIES)
    pols = ''
    for x in PARAMETRES:
        a = f'name="{x["id"]}" class="{x["classe"]}" displayName="$(string.{x["id"]})" explainText="$(string.{x["id"]}_Aide)" key={quoteattr(x["cle"])}'
        if x['elements']:
            a += f' presentation="$(presentation.{x["id"]})"'
        if x['type'] == 'bool' or x['valeur']:
            a += f' valueName="{x["valeur"] or x["id"]}"'
        corps = f'<parentCategory ref="{x["cat"]}"/><supportedOn ref="SUPPORTED_LinuxGPO"/>'
        if x['type'] == 'bool' or x['valeur']:
            corps += '<enabledValue><decimal value="1"/></enabledValue><disabledValue><decimal value="0"/></disabledValue>'
        if x['elements']:
            corps += '<elements>' + ''.join(_element(el, x['cle']) for el in x['elements']) + '</elements>'
        pols += f'    <policy {a}>{corps}</policy>\n'
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<!-- Généré par admx/generer.py (linux-gpo) : ne pas modifier à la main. -->\n'
            '<policyDefinitions xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'revision="1.0" schemaVersion="1.0" xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">\n'
            '  <policyNamespaces>\n    <target prefix="linuxgpo" namespace="LinuxGPO.Policies.LinuxGPO"/>\n'
            '    <using prefix="windows" namespace="Microsoft.Policies.Windows"/>\n  </policyNamespaces>\n'
            '  <resources minRequiredRevision="1.0"/>\n'
            '  <supportedOn>\n    <definitions>\n      <definition name="SUPPORTED_LinuxGPO" displayName="$(string.SUPPORTED_LinuxGPO)"/>\n'
            '    </definitions>\n  </supportedOn>\n'
            f'  <categories>\n{cats}  </categories>\n  <policies>\n{pols}  </policies>\n</policyDefinitions>\n')


def adml(langue: str) -> str:
    fr = langue == 'fr'
    chaines = {'SUPPORTED_LinuxGPO': 'Postes Linux avec l’agent linux-gpo' if fr else 'Linux computers running the linux-gpo agent'}
    for c, _, cfr, cen in CATEGORIES:
        chaines['cat_' + c] = cfr if fr else cen
    pres = ''
    for x in PARAMETRES:
        chaines[x['id']] = x['fr'] if fr else x['en']
        chaines[x['id'] + '_Aide'] = (x['aide_fr'] if fr else x['aide_en']) + ('\n\nAppliqué par linux-gpo (https://github.com/jonathan-pp/linux-gpo-agent).'
                                                                              if fr else '\n\nApplied by linux-gpo.')
        if not x['elements']:
            continue
        ctrl = ''
        for el in x['elements']:
            lib = escape(el['fr'] if fr else el['en'])
            t = el['type']
            if t == 'nombre':
                ctrl += f'<decimalTextBox refId="{el["id"]}" defaultValue="{el.get("defaut", 0)}">{lib}</decimalTextBox>'
            elif t == 'texte':
                d = f'<defaultValue>{escape(str(el["defaut"]))}</defaultValue>' if el.get('defaut') else ''
                ctrl += f'<textBox refId="{el["id"]}"><label>{lib}</label>{d}</textBox>'
            elif t == 'multi':
                ctrl += f'<multiTextBox refId="{el["id"]}">{lib}</multiTextBox>'
            elif t == 'case':
                ctrl += f'<checkBox refId="{el["id"]}">{lib}</checkBox>'
            elif t == 'choix':
                for n, cf, ce in el['choix']:
                    chaines[f'{el["id"]}_{n}'] = cf if fr else ce
                defaut = [n for n, _, _ in el['choix']].index(el['defaut']) if el.get('defaut') in [n for n, _, _ in el['choix']] else 0
                ctrl += f'<dropdownList refId="{el["id"]}" noSort="true" defaultItem="{defaut}">{lib}</dropdownList>'
            else:
                ctrl += f'<listBox refId="{el["id"]}">{lib}</listBox>'
        pres += f'      <presentation id="{x["id"]}">{ctrl}</presentation>\n'
    st = ''.join(f'      <string id="{k}">{escape(v)}</string>\n' for k, v in chaines.items())
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<!-- Généré par admx/generer.py (linux-gpo) : ne pas modifier à la main. -->\n'
            '<policyDefinitionResources xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'revision="1.0" schemaVersion="1.0" xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">\n'
            f'  <displayName>linux-gpo</displayName>\n  <description>{"Stratégies de groupe pour les postes Linux" if fr else "Group Policy for Linux computers"}</description>\n'
            f'  <resources>\n    <stringTable>\n{st}    </stringTable>\n    <presentationTable>\n{pres}    </presentationTable>\n  </resources>\n'
            '</policyDefinitionResources>\n')


def main():
    with open(os.path.join(ICI, 'LinuxGPO.admx'), 'w', encoding='utf-8') as fh:
        fh.write(admx())
    for d, l in (('fr-FR', 'fr'), ('en-US', 'en')):
        os.makedirs(os.path.join(ICI, d), exist_ok=True)
        with open(os.path.join(ICI, d, 'LinuxGPO.adml'), 'w', encoding='utf-8') as fh:
            fh.write(adml(l))
    with open(os.path.join(ICI, 'definitions.json'), 'w', encoding='utf-8') as fh:
        json.dump({'categories': CATEGORIES, 'parametres': PARAMETRES}, fh, ensure_ascii=False, indent=1)
    print(f'{len(PARAMETRES)} paramètres → LinuxGPO.admx, fr-FR, en-US, definitions.json')


if __name__ == '__main__':
    main()
