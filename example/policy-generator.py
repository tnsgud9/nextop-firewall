import json
import pprint
from dataclasses import asdict

from src.firewall.policy.policy_models import HttpPolicy

polices = [
    "adpacker.net",
    "ad.yna.co.kr",
    "veta.naver.com",
    "planad.net",
    "aedi.ai",
    "mobon.net",
    "nhnace.com",
    "splash-ad.classting.com",
    "ad-files.classting.com",
    "middlepoint.co.kr",
    "kiesta.net",
    "nsmartad.com",
    "authanalysis.com",
    "adfork.co.kr",
    "planmix.co.kr",
    "ads-api.kidsnote.com",
    "i18n-pglstatp.com",
    "unityads.unity3d.com",
    "pangolin*.sgsnssdk.com",
    "cp.edl.co.kr",
    "ad.*.doubleclick.net",
    "mediavisor.doubleclick.net",
    "static.doubleclick.net",
    "n4403ad.doubleclick.net",
    "g.doubleclick.net",
    "cdn-adn-*.rayjump.com",
    "net.rayjump.com",
    "vungle.com",
    "stream.spongead.com",
    "rainbownine.net",
    "ad-brix.com",
    "wtg-ads.com",
    "external-api.impression-neo.naver.com",
    "shoppingcall.me",
    "googletagservices.com",
    "bidr.io",
    "bidswitch.net",
    "taboola.com",
    "pubmatic.com",
    "3lift.com",
    "casalemedia.com",
    "33across.com",
    "openx.net",
    "criteo.com",
    "rubiconproject.com",
    "smartadserver.com",
    "lijit.com",
    "360yield.com",
    "quantserve.com",
    "criteo.net",
    "adnxs.com",
    "adskeeper.com",
    "widerplanet.com",
    "ad4989.co.kr",
    "marketingking.co.kr",
    "dable.io",
    "catad5959.com",
    "targetpush.co.kr",
    "netinsight.co.kr",
    "realclick.co.kr",
    "googleadservices.com",
    "ad-mapps.com",
    "acrosspf.com",
    "mobon.net",
    "adpnut.com",
    "thetopic.co.kr",
    "msadsense.com",
    "interworksmedia.co.kr",
    "adplex.co.kr",
    "tadapi.info",
    "clickmon.co.kr",
    "mrep.kr",
    "fastview.co.kr",
    "keywordsconnect.com",
    "adhooah.com",
    "contentsfeed.com",
    "mediacategory.com",
    "innorame.com",
    "ad.doubleclick.net",
    "adbinead.com",
    "cizion.com",
    "adop.cc",
    "stax.kr",
    "megadata.co.kr",
    "impactify.io",
    "teads.tv",
    "exelbid.com",
    "adinc.co.kr",
    "innity.net",
    "shoppingcall.me",
    "kodcad.kr",
    "hancomad.com",
    "ahnlabad.com",
    "tagtree.co.kr",
    "onepx.kr",
    "tapioni.com",
    "shukriya90.com",
    "trafficforce.com",
    "adbc.io",
    "realssp.co.kr",
    "bizspring.net",
    "nefing.com",
    "deployads.com",
    "mediabp.kr",
    "newscover.co.kr",
    "vrixon.com",
    "piclick.kr",
    "ads-twitter.com",
    "2mdn.net",
    "adxadserv.com",
    "admax.me",
    "nitropay.com",
    "bestcontentitem.top",
    "contentcave.co.kr",
    "adpopcorn.com",
    "koreanzad.xyz",
    "admonseller.com",
    "applovin.com",
    "andbeyond.media",
    "adlooxtracking.com",
    "aniview.com",
    "tnkad.net",
    "advertising.com",
    "contextweb.com",
    "ndexww.com",
    "adsrvr.org",
    "admanmedia.com",
    "sitescout.com",
    "undertone.com",
    "admaru.net",
    "pltapad.com",
    "mobwithad.com",
    "adxcorp.kr",
    "mmnneo.com",
    "amazon-adsystem.com",
    "tsyndicate.com",
    "vntsm.com",
    "optad360.io",
    "admixer.co.kr",
    "xlviirdr.com",
    "xn--s-4z5e652a53k.com",
    "categorysort.com",
    "tenping.kr",
    "infolinks.com",
    "adcastmarket.com",
]

http = {}
for p in polices:
    http[p] = asdict(
        HttpPolicy(
            method=None,
            headers=None,
            body=None,
            reason="250727 block policy",
            url=p,
            action="block",
        )
    )

print(json.dumps(http))
