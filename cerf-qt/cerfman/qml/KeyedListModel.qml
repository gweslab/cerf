import QtQuick

ListModel {
    id: keyed

    function apply(list) {
        const wanted = new Set(list.map(row => row.key))
        const keys = []
        for (let i = 0; i < keyed.count; ++i)
            keys.push(keyed.get(i).key)
        let end = keys.length
        while (end > 0) {
            if (wanted.has(keys[end - 1])) {
                --end
                continue
            }
            let start = end - 1
            while (start > 0 && !wanted.has(keys[start - 1]))
                --start
            keyed.remove(start, end - start)
            keys.splice(start, end - start)
            end = start
        }
        for (let i = 0; i < list.length; ++i) {
            const key = list[i].key
            const found = keys[i] === key ? i : keys.indexOf(key, i + 1)
            if (found < 0) {
                keyed.insert(i, list[i])
                keys.splice(i, 0, key)
                continue
            }
            if (found !== i) {
                keyed.move(found, i, 1)
                keys.splice(found, 1)
                keys.splice(i, 0, key)
            }
            keyed.set(i, list[i])
        }
    }
}
