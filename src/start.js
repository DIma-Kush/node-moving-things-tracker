const Tracker = require('./tracker');
let parsedDetections = require('../__mocks__/parsedDetections.json');
const detectionsFromYolo = require('../__mocks__/detectionsFromYolo.json');

console.log('!! 1.1 getFrames');
let res = Tracker.getJSONDebugOfTrackedItems();
console.log('!! 1.2 getFrames response ', JSON.stringify(res));

console.log('!! 2.1 updateFrames');

// Convert from
const convertPredictionsToTrackerFormat = (predictions) => predictions.reduce((acc, { score, name, rect }) => {
  acc.push({
    confidence: score,
    name,
    x: rect[0][0],
    y: rect[0][1],
    w: rect[1][0],
    h: rect[1][1],
  });

  return acc;
}, []);

parsedDetections = [convertPredictionsToTrackerFormat(detectionsFromYolo)];

parsedDetections.forEach((frame, frameNb) => {
  Tracker.updateTrackedItemsWithNewFrame(frame, frameNb);
});

console.log('!! 2.2 updateFrames done');
console.log('!! 3.1 getFrames');
res = Tracker.getJSONDebugOfTrackedItems();
console.log('!! 2.2 getFrames response ', JSON.stringify(res));
