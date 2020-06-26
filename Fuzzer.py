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
    def generate_random_name(self, name_length=8) -> (string):
        name = ''.join(random.choice(string.printable) for i in range(name_length))
        return name

    """add file to queue directory, and return the file name within the directory. Written file in binary mode"""
    def add_to_queue_directory(self, content) -> ([string]):
        file_name = self.generate_random_name()
        # generate filename and return path to file from working directory
        file_path = os.path.join(self.input_queue_directory, file_name)
        file = open(file_path, "wb")
        file.write(content)
        return [file_name]

    """read file called file_name from self.input_queue_directory"""
    def read_from_queue_directory(self, file_name) -> string:
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

    # todo
    def mutate(self, input_file) -> [[string]]:

        file_as_string = self.read_from_queue_directory(input_file)



        return