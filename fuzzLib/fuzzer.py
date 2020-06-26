# Standard Python Libraries
import os
import random
import string
from typing import List


class Fuzzer:
    def __init__(
        self,
        input_queue_directory="input_queue",
        min_printable: int = 0,
        max_printable: int = 255,
    ):
        """Initialize Fuzzer object class with default values."""
        self.MIN_PRINTABLE_CHAR = min_printable
        self.MAX_PRINTABLE_CHAR = max_printable
        self.input_queue_directory = input_queue_directory

    def generate_random_name(self, name_length=8) -> str:
        """Produce rand name."""
        name = "".join(
            random.choice(string.ascii_letters + string.digits)
            for i in range(name_length)
        )
        return name

    def add_to_queue_directory(self, content: bytes, name: str = "") -> str:
        """Add file to queue directory, and return the file name within the directory. Written file in binary mode."""
        # Generate file name
        file_name = f"{name}_{self.generate_random_name()}"

        # Define file path and write to file
        file_path = os.path.join(self.input_queue_directory, file_name)
        with open(file_path, "wb") as fp:
            fp.write(content)

        # Return random filename
        return file_name

    def read_from_queue_directory(self, file_name: str) -> bytes:
        """Read file called file_name from self.input_queue_directory."""
        # Define our filepath based on file_name
        file_path = os.path.join(self.input_queue_directory, file_name)

        # Read in file
        with open(file_path, "rb") as fp:
            file_content = fp.read()

        return file_content

    def generate_random_input_decimal(self, max_input_length=64) -> List[int]:
        """Generate random input sequence in Decimal. Draw random characters from pool of possible characters in their decimal representation."""
        # Define empty list for our gen'd input
        random_generated_input_sequence = []

        # Define random length
        random_length = random.randrange(0, max_input_length)

        # Build input integers, iterating over inegers
        for char in range(random_length):
            random_generated_input_sequence.append(
                random.randrange(self.MIN_PRINTABLE_CHAR, self.MAX_PRINTABLE_CHAR)
            )

        # Return the sequence of integers
        return random_generated_input_sequence

    def generate_random_input(self, max_input_length=64) -> bytes:
        """Generate random input sequence. Initially generate sequence as decimal and translates them to char."""
        # Define holders for byte conversions
        input_sequence_as_string = b""

        # Generate sequence of integers to convert to bytes
        input_sequence_as_decimals = self.generate_random_input_decimal(
            max_input_length=max_input_length
        )

        # Iterate over converting to string
        for character_index in range(len(input_sequence_as_decimals)):
            character_as_string = chr(
                input_sequence_as_decimals[character_index]
            )  # int -> string singleton
            character_as_byte = (
                character_as_string.encode()
            )  # string singleton -> bytestring singleton
            input_sequence_as_string += (
                character_as_byte  # bytestring singles -> bytestring
            )

        return input_sequence_as_string

    """generate "numbers of interest" """
    def generate_random_interesting_digit(self):
        random_interesting_digit_draw = random.randint(0, 1)
        if random_interesting_digit_draw == 0:
            return 0
        elif random_interesting_digit_draw == 1:
            # return (sys.maxint)
            return random.randint(0,255)
        else:
            return 0

    def stage_havoc(self, file_as_string) -> bytes:
        havoc_string = b''
        print(file_as_string)
        for char in bytearray(file_as_string):
            try:
                c = char.decode()
                if c.isdigit():
                    havoc_string += chr(self.generate_random_interesting_digit()).encode()
                else:
                    havoc_string += c.encode()
            except:
                havoc_string += chr(char).encode()
        return havoc_string

    def stage_splice(self) -> bytes:
        """Return input of spliced two inputs."""
        # Grab two input files
        try:
            directory = os.listdir(self.input_queue_directory)
            f1 = directory[random.randrange(0,len(directory)-1)]
            f2 = directory[random.randrange(0,len(directory)-1)]

            # Read in data
            file_1 = b""
            file_2 = b""
            with open(f"{self.input_queue_directory}/{f1}","rb") as fp:
                file_1 = fp.read()
            with open(f"{self.input_queue_directory}/{f2}", "rb") as fp:
                file_2 = fp.read()

            file_1 = file_1[:random.randint(0, len(file_1))]
            file_2 = file_2[:random.randint(0, len(file_2))]

            spliced_file = self.stage_havoc(file_1 + file_2)
        except:
            return b""
        return spliced_file

    def stage_flip1(self, data: bytes) -> bytes:
        """Stage to perform 1/1 bit flip defined in afl."""
        # Convert data in to bytearray
        data_arr = bytearray(data)

        # Bit flip the data
        for idx in range(len(data_arr)):
            # XOR With 0xFF will flip all bits. Byte is 8 bits
            data_arr[idx] = data_arr[idx] ^ 0xFF

        # Return mutated data
        return bytes(data_arr)

    def mutate(self, input_file) -> List[str]:
        """Orchestrate mutations which need to be done to file."""
        # Define empty list. Start with first name
        file_names = [input_file]
        # Read in data
        file_data = self.read_from_queue_directory(input_file)

        # Start mutation stages
        flip1 = self.stage_flip1(file_data)
        splice = self.stage_splice()

        # Write out our mutations
        file_names.append(self.add_to_queue_directory(flip1, input_file))
        file_names.append(self.add_to_queue_directory(splice, input_file))

        # Throw it back
        return file_names

    def get_input_file(self, data_len: int = 64) -> List[str]:
        """Generate input, write to file, then return singleton list."""
        # Generate file and write
        data = self.generate_random_input(data_len)
        names = self.add_to_queue_directory(data)

        # Return list
        return names
