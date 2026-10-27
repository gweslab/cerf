import QtQuick
import QtQuick.Controls

QtObject {
    id: flows
    required property Item defaultHost

    readonly property Component textPrompt: Component {
        TextPromptDialog {}
    }
    readonly property Component offerDialog: Component {
        UpdateOfferDialog {}
    }

    function richText(text) {
        return HtmlText.Escaped(String(text)).replace(/\n/g, "<br>")
    }

    function target(host) {
        return host ? host : defaultHost
    }

    function showDialog(host, props, done) {
        Dialogs.show(target(host), props, done)
    }

    function inform(title, message, host) {
        showDialog(host, {"title": title, "message": message})
    }

    function failed(reply, host) {
        if (reply.error === undefined)
            return false
        inform(reply.error.title, reply.error.message, host)
        return true
    }

    function ask(title, message, onYes, host) {
        Dialogs.ask(target(host), {"title": title, "message": message}, onYes)
    }

    function prompt(host, title, text, hints, done, value) {
        const dialog = textPrompt.createObject(target(host),
                                               {"title": title, "prompt": text, "hints": hints,
                                                "value": value !== undefined ? value : ""})
        dialog.done.connect(done)
        dialog.open()
    }

    function thanks(sources, host) {
        if (sources.length === 0)
            return
        const parts = sources.map(s => richText(s.credit) + "<br>"
                                       + qsTr("Would you like to %1 or %2?")
                                             .arg(HtmlText.Link(s.website, qsTr("pay them a visit")))
                                             .arg(HtmlText.Link(s.donate, qsTr("support them"))))
        showDialog(host, {"title": qsTr("ROM preservation"), "message": parts.join("<br><br>"), "rich": true})
    }

    function thankedRun(plan, host, run) {
        thanks(plan.thanks, host)
        run()
    }

    function download(keys, started) {
        const plan = RomDownloads.Plan(keys)
        if (plan.skipped !== undefined)
            inform(plan.skipped.title, plan.skipped.message)
        if (plan.keys === undefined)
            return
        thankedRun(plan, defaultHost, () => {
            RomDownloads.Start(plan.keys)
            started()
        })
    }

    function updateDevice(name, host) {
        const plan = RomDownloads.DevicePlan(name)
        if (failed(plan, host))
            return
        if (!plan.download) {
            RomDownloads.UpdateDevice(name, false)
            return
        }
        thankedRun(plan, host, () => RomDownloads.UpdateDevice(name, true))
    }

    function installPackage(name, pkg, host) {
        const plan = RomDownloads.PackagePlan(name, pkg.category, pkg.key)
        if (failed(plan, host))
            return
        thankedRun(plan, host, () => RomDownloads.InstallPackage(name, pkg.category, pkg.key))
    }

    function deletePackage(name, pkg, host) {
        ask(qsTr("Delete package"),
            qsTr("Remove %1 (%2)?\nThis cannot be undone.").arg(pkg.name)
                .arg(DeviceActions.RelativePath(name) + "/" + pkg.key),
            () => RomDownloads.DeletePackage(name, pkg.category, pkg.key), host)
    }

    function updateAll(host) {
        const plan = RomDownloads.UpdateAllPlan()
        if (plan.skipped !== undefined)
            inform(plan.skipped.title, plan.skipped.message, host)
        if (plan.nothing) {
            if (plan.skipped === undefined)
                inform(plan.upToDate.title, plan.upToDate.message, host)
            return
        }
        RomDownloads.UpdateAll()
    }

    function upgradeWhenClear(host) {
        const running = CerfUpdates.RunningCheck()
        if (running.title === undefined) {
            failed(CerfUpdates.Upgrade(), host)
            return
        }
        Dialogs.retry(target(host), running.title, running.message, again => { if (again) upgradeWhenClear(host) })
    }

    function offerUpgrade(host) {
        const offer = CerfUpdates.Offer()
        if (!offer.upgradable) {
            inform(offer.title, offer.message, host)
            return
        }
        const dialog = offerDialog.createObject(target(host), {"offer": offer})
        dialog.upgrade.connect(() => upgradeWhenClear(host))
        dialog.open()
    }
}
