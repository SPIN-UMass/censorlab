+++
title = "CensorLab"
extra.subtitle = "A Testbed for Censorship Experimentation"
extra.authors = [
    { name = "Jade Sheffey",    website = "https://cs.umass.edu/~jsheffey", institution = "umass" },
    { name = "Amir Houmansadr", website = "https://cs.umass.edu/~amir",     institution = "umass" }
]
extra.institutions = [
    { id = "umass", name = "University of Massachusetts Amherst", symbol = "§" }
]
extra.abstract = """Censorship and censorship circumvention are closely connected, and each is constantly making decisions in reaction to the other.
When censors deploy a new Internet censorship technique, the anti-censorship community scrambles to find and develop circumvention strategies against the censor's new strategy, i.e., by targeting and exploiting specific vulnerabilities in the new censorship mechanism. 
We believe that over-reliance on such a reactive approach to circumvention has given the censors the upper hand in the censorship arms race, becoming a key reason for the inefficacy of in-the-wild circumvention systems. 
Therefore, we argue for a proactive approach to censorship research: 
the anti-censorship community should be able to proactively develop circumvention mechanisms against hypothetical or futuristic censorship strategies.

To facilitate proactive censorship research, we design and implement CensorLab, a generic platform for emulating Internet censorship scenarios. CensorLab aims to complement currently reactive circumvention research  by efficiently emulating past, present, and hypothetical censorship strategies in  realistic network environments. Specifically,  CensorLab aims to (1) support all censorship mechanisms previously or currently deployed by real-world censors; (2) support  the emulation of hypothetical (not-yet-deployed) censorship strategies including advanced data-driven censorship mechanisms  (e.g., ML-based traffic classifiers); (3) provide an easy-to-use platform for researchers and practitioners enabling them to perform extensive experimentation; and (4) operate efficiently with minimal overhead.
We have implemented CensorLab as a fully functional, flexible, and high-performance platform, and showcase how it can be used to emulate a wide range of censorship scenarios, from traditional IP blocking and keyword filtering to hypothetical ML-based censorship mechanisms."""
extra.venue = ""
+++
