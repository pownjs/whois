const ipRangeCheck = require('ip-range-check')
const { makeId } = require('@pown/recon/lib/utils')
const { isIpv4 } = require('@pown/recon/lib/detect')
const { Transform } = require('@pown/recon/lib/transform')
const { IPV4_TYPE, IPV6_TYPE, DOMAIN_TYPE } = require('@pown/recon/lib/types')

const { whois } = require('../../lib/whois')

const WHOIS_REPORT_TYPE = 'whois:report'

const cache = {}

const whoisReport = class extends Transform {
    static get alias() {
        return ['whois_report', 'whois']
    }

    static get title() {
        return 'Whois Report'
    }

    static get description() {
        return 'Extract whois information.'
    }

    static get group() {
        return this.title
    }

    static get tags() {
        return ['ce']
    }

    static get types() {
        return [IPV4_TYPE, IPV6_TYPE, DOMAIN_TYPE]
    }

    static get options() {
        return {
            server: {
                type: 'string',
                describe: 'Server to query',
                default: ''
            },

            follow: {
                type: 'number',
                describe: 'Number of redirects to follow',
                default: 3
            },

            fastLookup: {
                type: 'boolean',
                describe: 'Perform as little whois lookups as possible',
                default: false
            },

            extractAsn: {
                type: 'boolean',
                describe: 'Extract asn nodes',
                default: false
            }
        }
    }

    static get priority() {
        return 1
    }

    static get noise() {
        return 5
    }

    async handle({ id: source = '', label = '' }, options) {
        const { fastLookup, extractAsn, ...whoisOptions } = options || {}

        const results = []

        let report

        if (fastLookup && isIpv4(label)) {
            for (let [cidr, cachedReport] of Object.entries(cache)) {
                if (cidr.split(/[\s,]+/).map(c => c.trim()).filter(c => c).some((c => ipRangeCheck(label, c)))) {
                    report = cachedReport
                }
            }
        }

        if (!report) {
            report = await whois(label, whoisOptions)
        }

        if (report) {
            const { organization, orgName = organization, netHandle = orgName, netName: label = netHandle } = report

            const id = makeId(WHOIS_REPORT_TYPE, label)

            results.push({ id, type: WHOIS_REPORT_TYPE, label, props: { ...report }, edges: [source] })

            if (extractAsn) {
                const { origin, originAs, asn = origin || originAs, organization } = report

                if (asn) {
                    results.push({ type: 'asn', lavbel: asn, props: { asn, organization }, edges: [source, id] })
                }
            }

            const { cidr } = report

            if (cidr) {
                cache[cidr] = report
            }
        }

        return results
    }
}

module.exports = { whoisReport }
