module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter num_nonces = 16;

enum logic [4:0] {IDLE, READ_1a, READ_1b, COMPUTE_0, COMPUTE_1a, COMPUTE_1b, COMPUTE_2a, WRITE_0, WRITE_1a, WRITE_1b} state;
logic [31:0] hout[num_nonces]; //final output H0s
logic [31:0] message_size;
logic is_last_sha; //for reusing compute block

logic [31:0] H0[num_nonces]; //H0-7 for 16 SHA blocks
logic [31:0] H1[num_nonces];
logic [31:0] H2[num_nonces];
logic [31:0] H3[num_nonces];
logic [31:0] H4[num_nonces];
logic [31:0] H5[num_nonces];
logic [31:0] H6[num_nonces];
logic [31:0] H7[num_nonces];

logic [31:0] message[19]; //19 words of message
logic [31:0] w[num_nonces][16]; //word array, first unpacked dim for each nonce, second for ith word in block

logic [31:0] A[num_nonces]; //A-H for 16 SHA blocks
logic [31:0] B[num_nonces];
logic [31:0] C[num_nonces];
logic [31:0] D[num_nonces];
logic [31:0] E[num_nonces];
logic [31:0] F[num_nonces];
logic [31:0] G[num_nonces];
logic [31:0] H[num_nonces];

logic [7:0] i;//i = sha compression round counter
logic [7:0] offset; // in word address
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;


assign message_size = 32'd640;

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

parameter int init_h[0:7] = '{
	32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19
};

// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals

    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k[t] + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};

endfunction

//Right Rotation
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction

//Function for Word Expansion
function logic [31:0] wtnew(input int w_i); // input w_i controls which nonce block to expand
logic [31:0] s0, s1;
s0 = rightrotate(w[w_i][1],7)^rightrotate(w[w_i][1],18)^(w[w_i][1]>>3);
s1 = rightrotate(w[w_i][14],17)^rightrotate(w[w_i][14],19)^(w[w_i][14]>>10);
wtnew = w[w_i][0] + s0 + w[w_i][9] + s1;
endfunction

// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;

//FSM COMB + SEQ LOGIC
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h for first stage, other variables and memory we, address offset, etc
    IDLE: begin 
		if(start) begin
		{H0[0],H1[0],H2[0],H3[0],H4[0],H5[0],H6[0],H7[0]} <= {init_h[0], init_h[1], init_h[2], init_h[3], init_h[4], init_h[5], init_h[6], init_h[7]};
		{A[0], B[0], C[0], D[0], E[0], F[0], G[0], H[0]} <= {init_h[0], init_h[1], init_h[2], init_h[3], init_h[4], init_h[5], init_h[6], init_h[7]};
		i <= 0;

		
		cur_addr <= message_addr;
		cur_we <= 0;
		offset <= 0;
		is_last_sha <= 0;
		state <= READ_1a;
		
		end
	 end
	//Read 19 words from memory into w (pipelined), then move to compute
	 READ_1a: begin
		cur_we <= 0;
		offset <= 1;
		state <= READ_1b;
	 end
	 
	 READ_1b: begin
		if(offset<8'd20) begin //offset goes 1 to 19 so offset-1 goes 0 to 18
		message[offset-1][31:0] <= mem_read_data;
	 
		cur_we <= 0;
		offset <= offset + 1;
		state <= READ_1b;
		end

		else begin 
		state <= COMPUTE_0; //for first round, 16 words = first 16 words of message
		for(int n = 0; n<16; n++) w[0][n] <= message[n];
		end
	 end
	 
	 //do first round of SHA256 on first 16 words
	 COMPUTE_0: begin
			if(i<64) begin
				
				if(i<48) begin //do 1 word expansion (first 16 already done, so only need 48 more) and 1 compression
				{A[0], B[0], C[0], D[0], E[0], F[0], G[0], H[0]} <= sha256_op(A[0], B[0], C[0], D[0], E[0], F[0], G[0], H[0], w[0][0], i);
				for (int m = 0; m < 15; m++) w[0][m] <= w[0][m+1]; // just wires
				w[0][15] <= wtnew(0);				
				end
				
				else if (i>=48) begin
				{A[0], B[0], C[0], D[0], E[0], F[0], G[0], H[0]} <= sha256_op(A[0], B[0], C[0], D[0], E[0], F[0], G[0], H[0], w[0][i-48], i);
				end
				
			i <= i+1;
			state <= COMPUTE_0;
			end
				
		  else begin //set h0-h7,a-h to be current stage hash + init hash used at input
		  {H0[0], H1[0], H2[0], H3[0], H4[0], H5[0], H6[0], H7[0]} <= {A[0]+H0[0], B[0]+H1[0], C[0]+H2[0], D[0]+H3[0], E[0]+H4[0], F[0]+H5[0], G[0]+H6[0], H[0]+H7[0]}; 
		  {A[0], B[0], C[0], D[0], E[0], F[0], G[0], H[0]} <= {A[0]+H0[0], B[0]+H1[0], C[0]+H2[0], D[0]+H3[0], E[0]+H4[0], F[0]+H5[0], G[0]+H6[0], H[0]+H7[0]}; 
		  i<= 0;
		  state <= COMPUTE_1a;
		  end
		  
	 end
	 
	 //set up w, h0-h7, a-h for 2nd round of parallel 16x SHA256 (second block of SHA)
	 COMPUTE_1a: begin
	 //set up w first
	 //first 3 words = msg, then nonce, then 32'h8000000, followed by 0s, then last two words are message size
	 for(int k = 0; k<num_nonces; k++) begin
			w[k][0] <= message[16];
			w[k][1] <= message[17];
			w[k][2] <= message[18]; 
			w[k][3] <= k; //nonce
			w[k][4] <= 32'h80000000;
			for(int n = 5; n<15; n++) begin //w[k][5-14] are 0s
				w[k][n] <= 32'h00000000;
			end
			w[k][15] <= message_size;
	 end
	 
	 //set up A-H and H0-H7; note that H0-H7[0] and A-H[0] are already set up
	 for(int k = 1; k<num_nonces; k++) begin
		{H0[k], H1[k], H2[k], H3[k], H4[k], H5[k], H6[k], H7[k]} <= {H0[0], H1[0], H2[0], H3[0], H4[0], H5[0], H6[0], H7[0]};
		{A[k], B[k], C[k], D[k], E[k], F[k], G[k], H[k]} <= {A[0], B[0], C[0], D[0], E[0], F[0], G[0], H[0]};
	 end
	 
	 state <= COMPUTE_1b;
	 end
	 
	 //do parallel 16x SHA256 compression for 64 rounds
	 COMPUTE_1b: begin
		if(i<64) begin
		
			//do 16x 1 word expansion and 16x 1 SHA compression (don't need to do word expansion for last 16 rounds
			for(int k=0; k<num_nonces; k++) begin
				{A[k], B[k], C[k], D[k], E[k], F[k], G[k], H[k]} <= sha256_op(A[k], B[k], C[k], D[k], E[k], F[k], G[k], H[k], w[k][i<48 ? 0: i-48], i);
			end
			if(i<48) begin 
				for(int k=0; k<num_nonces; k++) begin
					for(int n=0; n<15; n++) w[k][n] <= w[k][n+1]; //just wires
					w[k][15] <= wtnew(k);
					end
			end
			
			
			
			i<=i+1;
			state<=COMPUTE_1b;
		end
		//after SHA is done, set h0-h7,a-h to be current stage hash + init hash used at input
		else begin
			for(int k=0; k<num_nonces; k++) begin
				{H0[k], H1[k], H2[k], H3[k], H4[k], H5[k], H6[k], H7[k]} <= {A[k]+H0[k], B[k]+H1[k], C[k]+H2[k], D[k]+H3[k], E[k]+H4[k], F[k]+H5[k], G[k]+H6[k], H[k]+H7[k]}; 
				{A[k], B[k], C[k], D[k], E[k], F[k], G[k], H[k]} <= {A[k]+H0[k], B[k]+H1[k], C[k]+H2[k], D[k]+H3[k], E[k]+H4[k], F[k]+H5[k], G[k]+H6[k], H[k]+H7[k]};
			end
			i<=0;
			if(is_last_sha == 0)
			state<=COMPUTE_2a;
			else
			state<=WRITE_0;
		end

	 end
	 
	 //set up w, A-H, H0-H7 for final SHA block
	 COMPUTE_2a: begin
	 //set up w first, first 8 are output hash of previous, last 8 are 1, padding 0s, size=256 bits
		for(int k=0; k<num_nonces; k++) begin
			w[k][0] <= H0[k];
			w[k][1] <= H1[k];
			w[k][2] <= H2[k];
			w[k][3] <= H3[k];
			w[k][4] <= H4[k];
			w[k][5] <= H5[k];
			w[k][6] <= H6[k];
			w[k][7] <= H7[k];
			w[k][8] <= 32'h80000000;
			for(int n=9; n<15; n++) begin
				w[k][n] <= 32'h00000000;
			end
			w[k][15] <= 32'd256;
		end
		
		//set up A-H, H0-H7 as initial H const
		for(int k=0; k<num_nonces; k++) begin
			{H0[k],H1[k],H2[k],H3[k],H4[k],H5[k],H6[k],H7[k]} <= {init_h[0], init_h[1], init_h[2], init_h[3], init_h[4], init_h[5], init_h[6], init_h[7]};
			{A[k], B[k], C[k], D[k], E[k], F[k], G[k], H[k]} <= {init_h[0], init_h[1], init_h[2], init_h[3], init_h[4], init_h[5], init_h[6], init_h[7]};
		end
		
		state<= COMPUTE_1b; //computation is exactly the same as previous once all set up is done
		is_last_sha <= 1;
	 end
	 
	//get H0s ready to Write to memory
	WRITE_0: begin
		for(int k=0; k<num_nonces; k++) begin
			hout[k] <= H0[k];
		end

		
		state<= WRITE_1a;
	end
	 
	WRITE_1a: begin
		cur_we <= 1;
		offset <= 0;
		cur_addr <= output_addr;
		cur_write_data <= hout[0];
		state<=WRITE_1b;
	end
	
	WRITE_1b: begin
		if(offset<num_nonces-1) begin
			cur_we <= 1;
			cur_write_data <= hout[offset+1];
			offset <= offset+1;
			state<= WRITE_1b;
		end
		else state <= IDLE;
	end
	
	endcase
end
// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
