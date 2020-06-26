import codecs
import os
import random
import string
import sys

class Fuzzer:


    def __init__(self, input_queue_directory="input_queue"):
        # todo: note: max ascii values for now
        self.MIN_PRINTABLE_CHAR = 0 # todo: fix
        self.MAX_PRINTABLE_CHAR = 127 # todo: fix

        self.input_queue_directory = input_queue_directory
        if not (os.path.isdir(self.input_queue_directory)):
            os.mkdir(self.input_queue_directory)

        return

    """produce rand name"""
    def generate_random_name(self, name_length=8) -> string:
        name = ''.join(random.choice(string.printable) for i in range(name_length))
        return name

    """add file to queue directory, and return the file name within the directory. Written file in binary mode"""
    def add_to_queue_directory(self, content) -> [string]:
        file_name = self.generate_random_name()
        # generate filename and return path to file from working directory
        file_path = os.path.join(self.input_queue_directory, file_name)
        file = open(file_path, "wb")
        file.write(content)
        return [file_name]

    """read file called file_name from self.input_queue_directory"""
    def read_from_input_queue_directory(self, file_name) -> bytes:
        file_path = os.path.join(self.input_queue_directory, file_name)
        file = open(file_path, "rb")
        file_content = file.read()

        return file_content

    """generate random input sequence in Decimal. Draw random characters from pool of possible characters in their decimal representation"""
    def generate_random_input_decimal(self, max_input_length=64) -> [int]:
        random_generated_input_sequence = []

        random_length = random.randint(0, max_input_length)
        for char in range(random_length):
            new_character = random.randint(self.MIN_PRINTABLE_CHAR, self.MAX_PRINTABLE_CHAR) # inclusive on both ends
            random_generated_input_sequence.append(new_character)

        return random_generated_input_sequence

    """generates random input sequence. Initially generate sequence as decimal and translates them to char"""
    def generate_random_input(self, max_input_length=64) -> [string]:
        input_sequence_as_characters = []
        input_sequence_as_string = b""

        # iterative process of building input_sequence_as_characters from ..._as_decimals
        # note: singleton string means a string of 1 character.
        input_sequence_as_decimals = self.generate_random_input_decimal(max_input_length=max_input_length)

        for character_index in range(len(input_sequence_as_decimals)):
            character_as_string = chr(input_sequence_as_decimals[character_index]) # int -> string singleton
            character_as_bytestring = character_as_string.encode() # string singleton -> bytestring singleton
            input_sequence_as_string = input_sequence_as_string + character_as_bytestring #bytestring singles -> bytestring

        return input_sequence_as_string

    """compute the number of inputs in the queue directory"""
    def number_inputs_in_input_queue_directory(self) -> int:
        for (dir_path, dir_names, file_names) in os.walk(self.input_queue_directory):
            return (len(file_names) - 1)

    """reads and returns the file bytes at an index in the directory. Since this is used to grab random files, the directory isn't expected to maintain any order"""
    def get_file_content_at_random_index(self):
        drawn_file_index = random.randint(0, self.number_inputs_in_input_queue_directory())
        file_name = ""
        for (dir_path, dir_names, file_names) in os.walk(self.input_queue_directory):
            file_name = file_names[drawn_file_index]
            return self.read_from_input_queue_directory(file_name)

    """tbd"""
    def stage_flip1(self, file_as_string):
        return (~file_as_string)

    """generate "numbers of interest" """
    def generate_random_interesting_digit(self):
        random_interesting_digit_draw = random.randint(0, 1)
        if random_interesting_digit_draw == 0:
            return 0
        elif random_interesting_digit_draw == 1:
            # return (sys.maxint)
            return 100000100000100000 # big number?
        else:
            return 0
    """
    https://github.com/google/AFL/blob/c45fd010c83d0267b9f07eb976a7710776cd6a47/docs/status_screen.txt#L200
    havoc - a sort-of-fixed-length cycle with stacked random tweaks. The
    operations attempted during this stage include bit flips, overwrites with
    random and "interesting" integers, block deletion, block duplication, plus
    assorted dictionary-related operations (if a dictionary is supplied in the
    first place).
    
    we will do:
    - random bit flips
    - application of interesting integers
    - a version of block deletion where we just delete sequences of characters in the string
    
    """
    # todo: make better?
    def stage_havoc(self, file_as_string):
        havoc_string = b''
        for char in file_as_string.decode():
            if char.isdigit():
                havoc_string += self.generate_random_interesting_digit()
            else:
                havoc_string += char.encode()
        return havoc_string

    """splice together two inputs together at random midpoints, apply havoc"""
    def stage_splice(self, file_as_string) -> string:

        file_1 = self.get_file_content_at_random_index()
        file_1 = file_1[:random.randint(0, len(file_1))]

        file_2 = self.get_file_content_at_random_index()
        file_2 = file_2[:random.randint(0, len(file_2))]

        spliced_file = self.stage_havoc(file_1 + file_2)

        return spliced_file

    def mutate(self, input_file) -> [[string]]:

        file_as_string = self.read_from_input_queue_directory(input_file)
        # mutated_string_flip1 = self.add_to_queue_directory(self.stage_flip1(file_as_string))
        mutated_string_splice = self.add_to_queue_directory(self.stage_splice(file_as_string))

        return [input_file, mutated_string_splice[0]]
