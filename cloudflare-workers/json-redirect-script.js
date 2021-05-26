/**
 * For this to work add a route like:
 * json.distributedweaknessfiling.org/*	polished-pine-1b7e
 */

const baseDWF = "https://raw.githubusercontent.com/distributedweaknessfiling/dwflist/main/"
const baseSecurity = "https://raw.githubusercontent.com/distributedweaknessfiling/securitylist/main/"
const statusCode = 301

async function handleRequest(request) {
  const url = new URL(request.url)
  const { pathname } = url

/**
 * DWF CVE
 * pathname MUST equal CVE-NNNN-1NNNNNN
 * 2021/1000xxx/CVE-2021-1000011.json
 * NNNN/1NNNxxx/CVE-NNNN-1NNNNNN.json
 * https://raw.githubusercontent.com/distributedweaknessfiling/dwflist/main/2021/1000xxx/CVE-2021-1000010.json
 */

  const DWFCVEIDExtRegExp = new RegExp(/(CVE-202[1-9]-1[0-9][0-9][0-9][0-9][0-9][0-9])$/)
  /**
   * NVD data includes MITRE and original DWF data so:
   * CVE-YEAR-1234 
   * CVE-YEAR-12345 
   * CVE-YEAR-123456
   * CVE-201[4-9]-1234567 
   *  
   * 
   */ 

  const MITRECVE4IDExtRegExp = new RegExp(/(CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9])$/)
  const MITRECVE5IDExtRegExp = new RegExp(/(CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9])$/)
  const MITRECVE6IDExtRegExp = new RegExp(/(CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9])$/)
  /** 
   * Catch the old DWF assignments which are in the NVD database
  */
  const DWFpre2019IDExtRegExp = new RegExp(/(CVE-201[4-9]-1[0-9][0-9][0-9][0-9][0-9][0-9])$/)

  if (DWFCVEIDExtRegExp.test(pathname)) {
    var IDData = pathname.split("-")
    var DirRegExp = new RegExp(/([0-9][0-9][0-9])$/)
    var dirName = IDData[2].replace(DirRegExp, "xxx");
    const destinationURL = baseDWF + IDData[1] + "/" + dirName + pathname + ".json"
    return Response.redirect(destinationURL, statusCode)
  }

  if (MITRECVE4IDExtRegExp.test(pathname)) {
    var IDData = pathname.split("-")
    var DirRegExp = new RegExp(/([0-9][0-9][0-9])$/)
    var dirName = IDData[2].replace(DirRegExp, "xxx");
    const destinationURL = baseSecurity + IDData[1] + "/" + dirName + pathname + ".json"
    return Response.redirect(destinationURL, statusCode)
  }
  if (MITRECVE5IDExtRegExp.test(pathname)) {
    var IDData = pathname.split("-")
    var DirRegExp = new RegExp(/([0-9][0-9][0-9])$/)
    var dirName = IDData[2].replace(DirRegExp, "xxx");
    const destinationURL = baseSecurity + IDData[1] + "/" + dirName + pathname + ".json"
    return Response.redirect(destinationURL, statusCode)
  }
  if (MITRECVE6IDExtRegExp.test(pathname)) {
    var IDData = pathname.split("-")
    var DirRegExp = new RegExp(/([0-9][0-9][0-9])$/)
    var dirName = IDData[2].replace(DirRegExp, "xxx");
    const destinationURL = baseSecurity + IDData[1] + "/" + dirName + pathname + ".json"
    return Response.redirect(destinationURL, statusCode)
  }

  if (DWFpre2019IDExtRegExp.test(pathname)) {
    var IDData = pathname.split("-")
    var DirRegExp = new RegExp(/([0-9][0-9][0-9])$/)
    var dirName = IDData[2].replace(DirRegExp, "xxx");
    const destinationURL = baseSecurity + IDData[1] + "/" + dirName + pathname + ".json"
    return Response.redirect(destinationURL, statusCode)
  }

  else {
    const destinationURL = baseDWF + pathname
    return new Response("UNKNOWN DATA please use a valid CVE ID format", { status: 404 })
  }
}

addEventListener("fetch", async event => {
  event.respondWith(handleRequest(event.request))
})
