const core = require('@actions/core');
const appConfig = require('../app-cofig.js');
const { getVeracodeApplicationForPolicyScan, getVeracodeSandboxIDFromProfile, createSandboxRequest, getVeracodeApplicationScanStatus, getVeracodeApplicationFindings
} = require('./application-service.js');
const { downloadJar } = require('../api/java-wrapper.js');
const fs = require('fs');
const util = require('util');
const { exec, execFileSync } = require('child_process');
async function executeStaticScans(vid, vkey, appname, policy, teams, createprofile, gitRepositoryUrl, sandboxname, version, filepath){
    core.debug(`Getting Veracode Application for Policy Scan: ${appname}`)
    const veracodeApp = await getVeracodeApplicationForPolicyScan(vid, vkey, appname, policy, teams, createprofile, gitRepositoryUrl);
  if (veracodeApp.appId === -1) {
    core.setFailed(`Veracode application profile Not Found. Please create a profile on Veracode Platform, \
      or set "createprofile" to "true" in the pipeline configuration to automatically create profile.`);
    return;
  }
  core.info(`Veracode App Id: ${veracodeApp.appId}`);
  core.info(`Veracode App Guid: ${veracodeApp.appGuid}`);

  const jarName = await downloadJar();
  let sandboxID;
  let sandboxGUID;
    const buildId = version;

    const stat = util.promisify(fs.stat);
  const stats = await stat(filepath);

  if (stats.isFile()) {
    console.log(`${filepath} is a file.`);
  }else if (stats.isDirectory()) {
    console.log(`${filepath} is a directory.`);
  }

    const artifact = await fs.promises.readdir(filepath);

    try {
        if (sandboxname !== ''){
          core.info(`Running a Sandbox Scan: '${sandboxname}' on applicaiton: '${appname}'`);
          const sandboxes = await getVeracodeSandboxIDFromProfile(vid, vkey, veracodeApp.appGuid);
    
          core.info('Finding Sandbox ID & GUID');
          if (sandboxes.page.total_elements !== 0) {
            for (let i = 0; i < sandboxes._embedded.sandboxes.length; i++){
              if (sandboxes._embedded.sandboxes[i].name.toLowerCase() === sandboxname.toLowerCase()){
                sandboxID = sandboxes._embedded.sandboxes[i].id;
                sandboxGUID = sandboxes._embedded.sandboxes[i].guid
              }
              else {
                core.info(`Not the sandbox (${sandboxes._embedded.sandboxes[i].name}) we are looking for (${sandboxname})`);
              }
            }
          }
          if ( sandboxID == undefined && createsandbox == 'true'){
            core.debug(`Sandbox Not Found. Creating Sandbox: ${sandboxname}`);
            //create sandbox
            const createSandboxResponse = await createSandboxRequest(vid, vkey, veracodeApp.appGuid, sandboxname);
            core.info(`Veracode Sandbox Created: ${createSandboxResponse.name} / ${createSandboxResponse.guid}`);
            sandboxID = createSandboxResponse.id;
            sandboxGUID = createSandboxResponse.guid;
            //command to create sandbox scan
            core.info(`Veracode Sandbox Scan Created, Build Id: ${version}`);
            core.info('Static Scan Submitted, please check Veracode Platform for results');
      return;
          }
          else if ( sandboxID == undefined && createsandbox == 'false'){
            core.setFailed(`Sandbox Not Found. Please create a sandbox on Veracode Platform, \
            or set "createsandbox" to "true" in the pipeline configuration to automatically create sandbox.`);
            return;
          }
          else{
            core.info(`Sandbox Found: ${sandboxID} - ${sandboxGUID}`);
            //command to create sandbox scan
            core.info(`Veracode Sandbox Scan Created, Build Id: ${buildId}`);
            core.info('Static Scan Submitted, please check Veracode Platform for results');
      return;
          }
        }
        else{
          core.info(`Running a Policy Scan: ${appname}`);
          //comand for policy scan 
          core.info(`Veracode Policy Scan Created, Build Id: ${version}`);
          executePolicyScan(vid, vkey,veracodeApp, jarName, version, filepath)
        }
      } catch (error) {
        core.setFailed('Failed to create Veracode Scan. App not in state where new builds are allowed.');
        return;
      }

}

async function executePolicyScan(vid, vkey,veracodeApp, jarName, version, filepath){

    let policyScanCommand = `java -jar ${jarName} -action UploadAndScanByAppId -vid ${vid} -vkey ${vkey} -appid ${veracodeApp.appId} -filepath ${filepath} -version ${version} -scanpollinginterval 30 -autoscan true -scanallnonfataltoplevelmodules true -includenewmodules true -scantimeout 6000 -deleteincompletescan 2`;
    let scan_id  = '';
    let sandboxID;
  let sandboxGUID;
    const mylaunchDate = new Date();
    try {
       core.info(`Command to execute the policy scan : ${policyScanCommand}`);
        const output = execFileSync("java", ['-jar', `${jarName}`, '-action', 'UploadAndScanByAppId', '-vid', `${vid}`, '-vkey', `${vkey}`, '-appid', `${veracodeApp.appId}`, '-filepath', `${filepath}`, '-version', `${version}`, '-scanpollinginterval', '30', '-autoscan', 'true', '-scanallnonfataltoplevelmodules', 'true', '-includenewmodules', 'true', '-scantimeout', '6000', '-deleteincompletescan', '2']);
        core.info(`Output from trigger policy scan command : ${JSON.stringify(output)}`);
        scan_id = extractValue(output.stdout, 'The analysis id of the new analysis is "', '"');
    } catch (error) {
        const errorMesage = `Error while triggering policy scan for  ${error}`
        core.info(`Error while executing veracode policy scan command : ${policyScanCommand}: ${error}`);
        return;
    }

    core.info('Waiting for Scan Results...');
  let moduleSelectionStartTime = new Date();
  let moduleSelectionCount = 0;
  while (true) {
    await sleep(appConfig().pollingInterval);
    core.info('Checking Scan Results...');
    const statusUpdate = await getVeracodeApplicationScanStatus(vid, vkey, veracodeApp, version, sandboxID, sandboxGUID, jarName, mylaunchDate);
    core.info(`Scan Status: ${JSON.stringify(statusUpdate)}`);
    if (statusUpdate.status === 'MODULE_SELECTION_REQUIRED' || statusUpdate.status === 'PRE-SCAN_SUCCESS') {
      moduleSelectionCount++;
      if (moduleSelectionCount === 1)
        moduleSelectionStartTime = new Date();
      if (new Date() - moduleSelectionStartTime > appConfig().moduleSelectionTimeout) {
        core.setFailed('Veracode Policy Scan Exited: Module Selection Timeout Exceeded. ' +
          'Please review the scan on Veracode Platform.' + 
          `https://analysiscenter.veracode.com/auth/index.jsp#HomeAppProfile:${veracodeApp.oid}:${veracodeApp.appId}`);
        responseCode = SCAN_TIME_OUT;
        return responseCode;
      }
    }
    if ((statusUpdate.status === 'PUBLISHED' || statusUpdate.status == 'RESULTS_READY') && statusUpdate.scanUpdateDate) {
      const scanDate = new Date(statusUpdate.scanUpdateDate);
      const policyScanDate = new Date(statusUpdate.lastPolicyScanData);
      if (!policyScanDate || scanDate < policyScanDate) {
        if ((statusUpdate.passFail === 'DID_NOT_PASS' || statusUpdate.passFail == 'CONDITIONAL_PASS') && failbuild.toLowerCase() === 'true'){
          core.setFailed('Policy Violation: Veracode Policy Scan Failed');
          responseCode = POLICY_EVALUATION_FAILED;
        }
        else
          core.info(`Policy Evaluation: ${statusUpdate.passFail}`)
        break;
      } else {
        core.info(`Policy Evaluation: ${statusUpdate.passFail}`)
      }
    }
    
    if (endTime < new Date()) {
      core.setFailed(`Veracode Policy Scan Exited: Scan Timeout Exceeded`);
      responseCode = SCAN_TIME_OUT;
      return responseCode;
    }
  }
  await getVeracodeApplicationFindings(vid, vkey, veracodeApp, buildId, sandboxID, sandboxGUID);
  return responseCode;
}
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  export function extractValue(source,prefix, terminator){
    let start = source.search(prefix);
    let sub1 = source.substring(start + prefix.length);
    let end = sub1.search(terminator);
    return sub1.substring(0, end);
}
 
  module.exports = { executeStaticScans }