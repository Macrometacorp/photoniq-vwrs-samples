import { logger } from "log";
import VirtualWaitingRoom from "./virtualWaitingRoom.js";

const clientConnection = new VirtualWaitingRoom({
  apiKey: "YourAPIKey",
  vwrsMetricHost: "YourVwrsMetricUrl",
  vwrsHost: "YourVwrsURL",
  digestKey: "<false | true>",
  encryptionKey: "YourVwrsEncryptionKey",
  originAccessMode: "FIXED", //default is 'MOVING'(FIXED | MOVING),
});

export async function onClientRequest(request) {
  const reqOptions = {
    waitingRoomPath: "YourWaitingRoomPath",
    debugMode: true,
  };
  await clientConnection.handleVwrsRequest(request, reqOptions);
}

export async function onClientResponse(request, response) {
  logger.log("----on response-----");
  await clientConnection.handleVwrsResponse(request, response, {
    debugMode: true,
  });
}
