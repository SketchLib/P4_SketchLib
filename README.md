# P4_SketchLib

This is github repository for SketchLib published at NSDI '22. You can find paper link [here]([https://hnamkung.github.io/assets/pdf/nsdi22-sketchlib.pdf](https://www.usenix.org/conference/nsdi22/presentation/namkung).


General Instruction
- In the API folder, there is a list of optimizations/API in each p4 file.
- You can import the header file and can directly use the function call or you may modify it based on the content of the function call for your needs.
- We implemented 15 sketches using SketchLib, thus you can refer to these sketch implementations.
- We used Tofino SDE version 9.1.1

Sketchovsky (NSDI '23) is extension of SketchLib [[Paper link]](https://www.usenix.org/conference/nsdi23/presentation/namkung) [[github link]](https://github.com/sketchovsky)
- SketchLib only focuses on running a single sketch instance. Sketchovsky runs multiple sketch instances simultaneously.
