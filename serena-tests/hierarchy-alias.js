const { exec } = require('child_process');

class ImageProcessor {
  constructor(options) {
    this.options = options;
  }

  // Vulnerable method if 'cmd' is tainted
  runCommand(cmd) {
    exec(cmd, (err, stdout) => {
      console.log(stdout);
    });
  }
}

function processImage(filename) {
  // Aliasing
  const target = filename;
  const processor = new ImageProcessor({});
  
  // Complex string construction
  const command = `convert ${target} output.png`;
  
  // Call hierarchy: processImage -> ImageProcessor.runCommand
  processor.runCommand(command);
}

// Entry point
module.exports = (req, res) => {
  // Serena should link 'req.body.image' -> 'filename' -> 'target' -> 'command' -> 'runCommand'
  processImage(req.body.image);
};
