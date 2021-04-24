/**
 * For this to work add a route like:
 * json.distributedweaknessfiling.org/*	polished-pine-1b7e
 */

const base = "https://raw.githubusercontent.com/distributedweaknessfiling/dwflist/main/"
const statusCode = 301

async function handleRequest(request) {
  const url = new URL(request.url)
  const { pathname } = url

/**
 * pathname MUST equal CVE-NNNN-1NNNNNN
 * 2021/1000xxx/CVE-2021-1000011.json
 * NNNN/1NNNxxx/CVE-NNNN-1NNNNNN.json
 * https://raw.githubusercontent.com/distributedweaknessfiling/dwflist/main/2021/1000xxx/CVE-2021-1000010.json
 */

  const IDExtRegExp = new RegExp(/(CVE-[0-9][0-9][0-9][0-9]-1[0-9][0-9][0-9][0-9][0-9][0-9])$/)

  if (IDExtRegExp.test(pathname)) {
    var IDData = pathname.split("-")
    var DirRegExp = new RegExp(/([0-9][0-9][0-9])$/)
    var dirName = IDData[2].replace(DirRegExp, "xxx");
    const destinationURL = base + IDData[1] + "/" + dirName + pathname + ".json"
    return Response.redirect(destinationURL, statusCode)
  }
  else {
    const destinationURL = base + pathname
    return new Response("UNKNOWN DATA please use CVE-NNNN-1NNNNNN", { status: 404 })
  }
}

addEventListener("fetch", async event => {
  event.respondWith(handleRequest(event.request))
})
