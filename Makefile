
keygen:
	go run ./cmd/keygen --id 1 --n 5 --t 2 --init --output round0_out_1.json --state state1.json
	go run ./cmd/keygen --id 2 --n 5 --t 2 --init --output round0_out_2.json --state state2.json
	go run ./cmd/keygen --id 3 --n 5 --t 2 --init --output round0_out_3.json --state state3.json
	go run ./cmd/keygen --id 4 --n 5 --t 2 --init --output round0_out_4.json --state state4.json
	go run ./cmd/keygen --id 5 --n 5 --t 2 --init --output round0_out_5.json --state state5.json
	# round 1
	go run ./cmd/keygen --id 1 --round1 --input round0_out_1.json,round0_out_2.json,round0_out_3.json,round0_out_4.json,round0_out_5.json --output round1_tmpsec1.dat --state state1.json
	go run ./cmd/keygen --id 2 --round1 --input round0_out_1.json,round0_out_2.json,round0_out_3.json,round0_out_4.json,round0_out_5.json --output round1_tmpsec2.dat --state state2.json
	go run ./cmd/keygen --id 3 --round1 --input round0_out_1.json,round0_out_2.json,round0_out_3.json,round0_out_4.json,round0_out_5.json --output round1_tmpsec3.dat --state state3.json
	go run ./cmd/keygen --id 4 --round1 --input round0_out_1.json,round0_out_2.json,round0_out_3.json,round0_out_4.json,round0_out_5.json --output round1_tmpsec4.dat --state state4.json
	go run ./cmd/keygen --id 5 --round1 --input round0_out_1.json,round0_out_2.json,round0_out_3.json,round0_out_4.json,round0_out_5.json --output round1_tmpsec5.dat --state state5.json
	# round 2
	go run ./cmd/keygen --id 1 --round2 --input round1_out_2_1.json,round1_out_3_1.json,round1_out_4_1.json,round1_out_5_1.json --output final_key_participant1 --state state1.json
	go run ./cmd/keygen --id 2 --round2 --input round1_out_1_2.json,round1_out_3_2.json,round1_out_4_2.json,round1_out_5_2.json --output final_key_participant2 --state state2.json
	go run ./cmd/keygen --id 3 --round2 --input round1_out_1_3.json,round1_out_2_3.json,round1_out_4_3.json,round1_out_5_3.json --output final_key_participant3 --state state3.json
	go run ./cmd/keygen --id 4 --round2 --input round1_out_1_4.json,round1_out_2_4.json,round1_out_3_4.json,round1_out_5_4.json --output final_key_participant4 --state state4.json
	go run ./cmd/keygen --id 5 --round2 --input round1_out_1_5.json,round1_out_2_5.json,round1_out_3_5.json,round1_out_4_5.json --output final_key_participant5 --state state5.json

sign:
	go run ./cmd/sign --signers 1,2,3 --init --secret final_key_participant1_sec.dat --shares final_key_participant1_pub.json --message README.md --output sign_round0_1.json --state sign_state1.json
	go run ./cmd/sign --signers 1,2,3 --init --secret final_key_participant2_sec.dat --shares final_key_participant2_pub.json --message README.md --output sign_round0_2.json --state sign_state2.json
	go run ./cmd/sign --signers 1,2,3 --init --secret final_key_participant3_sec.dat --shares final_key_participant3_pub.json --message README.md --output sign_round0_3.json --state sign_state3.json
	# round 1
	go run ./cmd/sign --id 1 --round1 --input sign_round0_2.json,sign_round0_3.json --output sign_round1_1.json --state sign_state1.json
	go run ./cmd/sign --id 2 --round1 --input sign_round0_1.json,sign_round0_3.json --output sign_round1_2.json --state sign_state2.json
	go run ./cmd/sign --id 3 --round1 --input sign_round0_1.json,sign_round0_2.json --output sign_round1_3.json --state sign_state3.json
	# round 2
	go run ./cmd/sign --id 1 --round2 --input sign_round1_2.json,sign_round1_3.json --state sign_state1.json --output final_signature_1.sig
	@#go run ./cmd/sign --id 2 --round2 --input sign_round1_1.json,sign_round1_3.json --state sign_state2.json --output final_signature_2.sig
	@#go run ./cmd/sign --id 3 --round2 --input sign_round1_1.json,sign_round1_2.json --state sign_state3.json --output final_signature_3.sig

sign2:
	go run ./cmd/sign --signers 1,2 --init --secret final_key_participant1_sec.dat --shares final_key_participant1_pub.json --message README.md --output sign_round0_1.json --state sign_state1.json
	go run ./cmd/sign --signers 1,2 --init --secret final_key_participant2_sec.dat --shares final_key_participant2_pub.json --message README.md --output sign_round0_2.json --state sign_state2.json
	# round 1
	go run ./cmd/sign --id 1 --round1 --input sign_round0_2.json --output sign_round1_1.json --state sign_state1.json
	go run ./cmd/sign --id 2 --round1 --input sign_round0_1.json --output sign_round1_2.json --state sign_state2.json
	# round 2
	go run ./cmd/sign --id 1 --round2 --input sign_round1_2.json --state sign_state1.json --output final_signature_1.sig
	@#go run ./cmd/sign --id 2 --round2 --input sign_round1_1.json --state sign_state2.json --output final_signature_2.sig

clean:
	rm *.json
	rm *.dat
	rm *.sig
