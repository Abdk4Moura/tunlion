// Speakable pairing wordlists: CLIENT-SIDE minting (spec SS2.0).
// 256 adj x 256 animal = 65,536 (2^16) password space.
// These lists MUST be byte-identical to pake/src/words.rs ADJ/ANIMAL.

export const ADJ = [
  'amber','bold','brave','brisk','calm','cheery','chill','civil',
  'clever','cosy','crisp','daring','deft','dewy','eager','early',
  'fancy','fiery','fleet','fond','frank','free','fresh','gentle',
  'giddy','glad','golden','grand','happy','hardy','hasty','honest',
  'humble','jolly','keen','kind','lively','loyal','lucky','lunar',
  'mellow','merry','mighty','misty','neat','noble','perky','plucky',
  'polar','proud','quick','quiet','rapid','rosy','royal','shiny',
  'snappy','solid','spry','stout','sunny','tidy','witty','able',
  'actual','adept','agile','alert','aloft','ample','apt','ardent',
  'avid','aware','basic','blithe','bonny','bouncy','breezy','bright',
  'bubbly','buxom','candid','chunky','classy','comfy','comic','composed',
  'cordial','craggy','cuddly','curly','dainty','dapper','dazzling','decent',
  'dense','distant','dopey','drowsy','dry','elegant','elite','faint',
  'feeble','festive','fickle','flaky','flimsy','fluffy','foamy','focused',
  'frosty','frothy','frugal','furry','fuzzy','gaudy','gawky','genuine',
  'giant','gifted','gleaming','gloomy','glossy','glum','grainy','greedy',
  'green','grimy','gritty','groggy','groovy','grouchy','grumpy','gusty',
  'hairy','hale','handy','hearty','hefty','hip','hoarse','icy',
  'ideal','idle','jazzy','jovial','joyful','keenly','kooky','lanky',
  'lax','leafy','lean','leery','legal','light','limber','lime',
  'limp','livid','lofty','loose','lousy','lucid','lumpy','lurid',
  'lush','lusty','mad','major','mangy','manic','mere','messy',
  'mild','milky','minimal','minor','mint','mod','moist','moody',
  'muddy','muggy','mundane','murky','mushy','musty','mute','narrow',
  'nasty','naughty','nervy','nimble','nippy','noisy','nosy','novel',
  'oily','ornate','pale','palmy','peppy','pesky','petite','picky',
  'pithy','placid','plump','plush','poised','presto','prim','prime',
  'prompt','pure','quirky','ragged','randy','rash','raw','ready',
  'remote','ridged','right','rigid','ripe','risky','ritzy','robust',
  'rocky','roomy','rough','round','rowdy','rude','rustic','rusty',
  'sandy','saucy','savvy','sharp','sheer','shifty','short','showy',
  'shrewd','shy','silken','silky','silly','sleek','sleepy','slender',
]

export const ANIMAL = [
  'otter','panda','falcon','lynx','koala','heron','fox','ibex',
  'marten','tapir','badger','beaver','bison','bongo','camel','civet',
  'condor','crane','dingo','dove','eland','ermine','ferret','finch',
  'gecko','gibbon','hare','hawk','hyrax','jackal','kestrel','kiwi',
  'lemur','llama','macaw','magpie','mole','moose','murre','newt',
  'ocelot','okapi','oriole','osprey','owl','pika','plover','puffin',
  'quokka','rabbit','raven','robin','seal','shrew','skink','sparrow',
  'stoat','swan','tern','toucan','vole','wombat','wren','zebra',
  'aardvark','agouti','akita','alpaca','anchovy','antelope','armadillo','baboon',
  'barracuda','basilisk','bass','bat','beagle','bee','bengal','blenny',
  'boar','bobcat','bonobo','bonito','boxer','bronco','budgie','buffalo',
  'bulldog','bullfrog','bunting','burro','butterfly','buzzard','calf','canary',
  'capybara','caribou','carp','catbird','catfish','chameleon','cheetah','chickadee',
  'chihuahua','chipmunk','chow','cicada','clam','clownfish','cobra','cockatoo',
  'collie','conch','coot','corgi','cormorant','cougar','cowbird','coyote',
  'crab','crayfish','cricket','crow','cuckoo','curlew','cuttle','dachshund',
  'damsel','darter','deer','devil','dhole','dikdik','dipper','doberman',
  'dogfish','dolphin','donkey','dormouse','dragonfly','drake','dunlin','eagle',
  'echidna','eel','egret','elephant','elk','emu','fallow','fennec',
  'firefly','flamingo','flounder','fossa','frog','gar','gazelle','gerbil',
  'giraffe','gnat','gnu','goat','goldfinch','goose','gopher','gorilla',
  'gosling','greyhound','grouse','gull','guppy','hamster','hedgehog','hen',
  'hermit','hippo','hornet','horse','hound','hummingbird','hyena','iguana',
  'impala','jackrabbit','jaguar','jay','jellyfish','jerboa','junco','kakapo',
  'kangaroo','katydid','kingfisher','kinkajou','kite','kitten','koi','krill',
  'lab','ladybug','lamb','lamprey','lemming','leopard','liger','lion',
  'lizard','lobster','locust','loon','loris','louse','macaque','mackerel',
  'maggot','mallard','maltese','manatee','mandrill','manta','mare','marmoset',
  'marmot','mastiff','meerkat','mink','minnow','monarch','mongoose','monkey',
  'moth','mouse','mule','muskox','mussel','mustang','narwhal','nautilus',
  'nightjar','numbat','nuthatch','octopus','olm','opossum','orangutan','orca',
  'oryx','ostrich','ox','oyster','panther','parrot','partridge','peacock',
]

export const EXTRA = [
  'azure','cobalt','coral','crimson','emerald','hazel','indigo','ivory',
  'jade','lilac','olive','rose','ruby','scarlet','teal','violet',
]


function pick(list) {
  const buf = new Uint32Array(1)
  crypto.getRandomValues(buf)
  return list[buf[0] & (list.length - 1)]
}

export function mintWords() {
  return `${pick(ADJ)}-${pick(ANIMAL)}`
}

export function mintNameplate() {
  const buf = new Uint32Array(1)
  crypto.getRandomValues(buf)
  return String(100 + (buf[0] % 900))
}

export function validateChosenPassword(raw, userName) {
  const trimmed = raw.replace(/^-+|-+$/g, '')
  const parts = trimmed.split('-').filter(s => s !== '')
  if (parts.length < 2) {
    return 'at least two distinct words (e.g. happy-dolphin or bold-panda)'
  }
  const words = parts.filter(w => w !== 'and' && w !== 'the')
  if (words.length < 2) {
    return 'at least two distinct words; try a different phrase'
  }
  for (let i = 0; i < words.length; i++) {
    for (let j = i + 1; j < words.length; j++) {
      if (words[i].toLowerCase() === words[j].toLowerCase()) {
        return `the word '${words[i]}' appears twice; pick two different words`
      }
    }
  }
  const lower = trimmed.toLowerCase()
  const blocklist = [
    'hello-world','let-me-in','test-test','test-test-test',
    'open-says-me','abracadabra','sesame-open','trust-no-one',
    'top-secret','secret-code','secret-sauce','no-secret',
    'my-code','my-password','the-code','the-password',
    'pass-word','enter-now','let-me','come-in',
    'good-morning','good-evening','good-night','good-afternoon',
    'thank-you','you-are-welcome','how-are-you','i-am-fine',
    'nice-to-meet-you','see-you-later','take-care','have-fun',
    'love-you','miss-you','happy-birthday','merry-christmas',
    'happy-new-year','happy-holidays','best-wishes','good-luck',
    'one-two','two-three','three-four','four-five',
    'alpha-beta','beta-gamma','foo-bar','baz-qux',
  ]
  if (blocklist.includes(lower)) {
    return `'${trimmed}' is too predictable; try a less obvious phrase`
  }
  const nameLower = (userName || '').trim().toLowerCase()
  if (nameLower && nameLower !== 'anonymous') {
    for (const w of words) {
      if (w.toLowerCase() === nameLower) {
        return `don't use your own device name in the code; anyone who knows your name would guess it first`
      }
    }
  }
  return null
}
