const Tracker = require('./tracker');

const detections = [
    [
        {
            x: 0.688212,
            y: 0.755398,
            w: 0.026031,
            h: 0.048941,
            confidence: 16.5444,
            name: 'object',
        },
    ],
    [], // This empty frame ensure that the object will be removed if fastDelete is enabled.
    [
        {
            x: 0.686925,
            y: 0.796403,
            w: 0.028142,
            h: 0.050919,
            confidence: 25.7651,
            name: 'object',
        },
    ],
    [
        {
            x: 0.686721,
            y: 0.837579,
            w: 0.027887,
            h: 0.054398,
            confidence: 34.285399999999996,
            name: 'object',
        },
    ],
    [
        {
            x: 0.686436,
            y: 0.877328,
            w: 0.026603,
            h: 0.058,
            confidence: 18.104300000000002,
            name: 'object',
        },
    ],
];


console.log("!! 1.1 getFrames")
var res = Tracker.getJSONOfTrackedItems();
console.log("!! 1.2 getFrames response ", JSON.stringify(res))

console.log("!! 2.1 updateFrames")
detections.forEach((frame, frameNb) => {
    Tracker.updateTrackedItemsWithNewFrame(frame, frameNb);
});
console.log("!! 2.2 updateFrames done")

console.log("!! 3.1 getFrames")
res = Tracker.getJSONOfTrackedItems();
console.log("!! 2.2 getFrames response ", JSON.stringify(res))