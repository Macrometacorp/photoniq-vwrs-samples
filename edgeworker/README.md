# PhotonIQ VWRS EdgeWorker Library v1.24.0

This EdgeWorker library is used to configure a virtual waiting room.

### Configuration

You can pass the following configuration

```
   apiKey: "YourAPIKey",
   vwrsMetricHost: "YourVwrsMetricHost",
   vwrsHost: "YourVwrsHost",
   isFailOpen|boolean|: set it to 'true' to navigate to origin in case of failure,(default to true)
   digestKey:"YourVwrsDigestKey",
   encryptionKey: "YourVwrsEncryptionKey",
   originAccessMode: "ORIGIN_USAGE_TIME", //default is 'ORIGIN_IDLE_TIME'(ORIGIN_USAGE_TIME | ORIGIN_IDLE_TIME),
   statusConfigLimits:{
      avgWaitingTime:true|false,
      qDepth: true|false,
      position: true|false,
    } : set values in statusConfigLimits as true to restrict them in the status call.(defaults to false)

```

### Sample Code

```
import { logger } from "log";
import VirtualWaitingRoom from "./virtualWaitingRoom.js";

const virtualWaitingRoom = new VirtualWaitingRoom({
  apiKey: "YourAPIKey",
  vwrsMetricHost: "YourVwrsMetricUrl",
  vwrsHost: "YourVwrsURL",
  isFailOpen: "<false | true>", // will be boolean value true by default
  digestKey: "<false | true>",
  encryptionKey: "YourVwrsEncryptionKey",
  originAccessMode: "<ORIGIN_USAGE_TIME | ORIGIN_IDLE_TIME>", //default is 'ORIGIN_USAGE_TIME',
  statusConfigLimits:{
    avgWaitingTime:<true | false>, //default is 'false'
    qDepth: <true | false>, //default is 'false'
    position: <true | false>, //default is 'false'
  }
});

export async function onClientRequest(request) {
  logger.log("---- on request -----");
  const reqOptions = {
    waitingRoomPath:'/1473985/doc.html',
    extraFingerPrint: ['something'],
    debugMode: true, //default is false
  };
  await virtualWaitingRoom.handleVwrsRequest(request,reqOptions);
}

export async function onClientResponse(request, response) {
  logger.log("---- on response -----");
  const reqOptions = {
    extraFingerPrint: ['something'],
    debugMode: true, //default is false
  };

  await virtualWaitingRoom.handleVwrsResponse(request, response,reqOptions);
```

## PMUSER_VSC

```
Nomenclature: STATUS TYPE OBJECT VERB/ADJECTIVE
STATUS = SUCCESS | ERROR
TYPE = HTTP | SECURITY | ROUTE

```

### Description

<table>
  <tr>
    <th>Status Code</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>SROL</td>
    <td>Successfully routed to origin live</td>
  </tr>
  <tr>
    <td>SRWL</td>
    <td>Successfully routed to the waiting room live</td>
  </tr>
  <tr>
    <td>SRWP</td>
    <td>Successfully routed to the waiting room preview</td>
  </tr>
  <tr>
    <td>SHSL</td>
    <td>Successfully fetched queue status live</td>
  </tr>
  <tr>
    <td>SHSP</td>
    <td>Successfully fetched queue status preview</td>
  </tr>
  <tr>
    <td>EHDD</td>
    <td>Error getting domain details</td>
  </tr>
  <tr>
    <td>EHRS</td>
    <td>Error getting request status</td>
  </tr>
  <tr>
    <td>EHRP</td>
    <td>Error pushing request to queue</td>
  </tr>
  <tr>
    <td>EHMN</td>
    <td>Error in metrics notification</td>
  </tr>
  <tr>
    <td>EHQD</td>
    <td>Error getting queue depth</td>
  </tr>
  <tr>
    <td>ESCE</td>
    <td>Error in cookie encryption</td>
  </tr>
  <tr>
    <td>ESCD</td>
    <td>Error in cookie decryption</td>
  </tr>
  <tr>
    <td>ESCC</td>
    <td>Error cookie createdAt</td>
  </tr>
  <tr>
    <td>ESDC</td>
    <td>Error in digest creation</td>
  </tr>
  <tr>
    <td>ESTE</td>
    <td>Token does not exist</td>
  </tr>
  <tr>
    <td>ESER</td>
    <td>Error in encryption raw-key creation</td>
  </tr>
</table>

### Key PM_USER Variables

- **PMUSER_VSC**: Represents the Virtual Waiting Room Status Code.
- **PMUSER_FL**: Indicates the Waiting Room Flow. Possible values:
  - `NWR`: No Waiting Room
  - `IS`: Insecure
  - `NO`: Normal
  - `IE`: Ingress Error
- **PMUSER_AWT**: Stands for Average Waiting Time.
- **PMUSER_VP**: Refers to Persisted Data.
- **PMUSER_RC**: Denotes the Subrequest Count.

### Debug Mode

In debug mode, the `type` variable in the debug header provides insight into user status:

- `A`: Access - Indicates that the user has been moved to origin access, and an access type of cookie is generated.
- `S`: Session - Indicates that the user is in the waiting room, and a session type of cookie is generated.
