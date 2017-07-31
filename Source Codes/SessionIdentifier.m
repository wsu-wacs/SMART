%                             Copyright (C) <2017> 
%                        Mahdieh ZabihiMayvan, Reza Sadeghi   
%     Department of Computer Science and Engineering, Kno.e.sis Research Center, 
%                Wright State University, Dayton, OH, USA
% 
%     This program is free software: you can redistribute it and/or modify
%     it under the terms of the GNU General Public License as published by
%     the Free Software Foundation, either version 3 of the License, or
%     any later version.
% 
%     This program is distributed under the License on an "AS IS" BASIS,
%     but WITHOUT ANY WARRANTY; without even the implied warranty of
%     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%     GNU General Public License for more details.
% 
%     You should have received a copy of the GNU General Public License
%     along with this program.  If not, see <http://www.gnu.org/licenses/>.
%
%     Using this code or any associated file of this package in a publication, 
%     please CITE the related paper as below:
%
%     Zabihimayvan, Mahdieh, Reza Sadeghi, H. Nathan Rude, and Derek Doran. 
%     "A Soft Computing Approach for Benign and Malicious Web Robot Detection." 
%     Expert Systems with Applications 87 (2017) 129-140.

%     If you have any questions concerning the implementation of the code, 
%     please feel free to contact us via email addresses below:

%     Zabhimayvan.2@wright.edu, mahdieh@knoesis.org, sadeghi.2@wright.edu,
%     reza@knoesis.org.


function [SessionNumber,SessionIndex]=SessionIdentifier(IP,UserAgent,DateTime)
DataNumber=numel(IP);
SessionIndex=zeros(DataNumber,1);
SessionState=zeros(DataNumber,1);%0->Unseen 1->Open 2->Closed

SessionNumber=1;% New Session
SelectedRequest=1;
SessionIndex(SelectedRequest)=SessionNumber;
SessionState(SelectedRequest)=1;% Open
for NewRequest=2:DataNumber
    if(strcmp(IP(SelectedRequest),IP(NewRequest)) || strcmp(UserAgent(SelectedRequest),UserAgent(NewRequest)))
        TimeElapsed=etime(datevec(DateTime(NewRequest)),datevec(DateTime(SelectedRequest)));
        TimeElapsed=TimeElapsed<=1800;%30min is 1800sec
        if(TimeElapsed)
            SessionIndex(NewRequest)=SessionIndex(SelectedRequest);
            SessionState(NewRequest)=1;%Open This
            SelectedRequest=NewRequest;
        else
            SessionState(find(SessionIndex==SessionIndex(SelectedRequest)))=2;%Closed
            RequestsOfOpenSessions=find(SessionState==1);
            if(numel(RequestsOfOpenSessions)>0)
                SelectedRequest=RequestsOfOpenSessions(find(strcmp(IP(RequestsOfOpenSessions),IP(NewRequest)) + strcmp(UserAgent(RequestsOfOpenSessions),UserAgent(NewRequest)),1,'last'));
                if (numel(SelectedRequest)==0)% There is not a match session
                    SessionState(NewRequest)=1;%Open This 
                    SessionNumber=SessionNumber+1;% New Session
                    SessionIndex(NewRequest)=SessionNumber;
                    SelectedRequest=NewRequest;
                    continue;
                end
                SelectedRequest=find(SessionIndex==SessionIndex(SelectedRequest),1,'last');%It is the last request in a certain session
                TimeElapsed=etime(datevec(DateTime(NewRequest)),datevec(DateTime(SelectedRequest)));
                TimeElapsed=TimeElapsed<=1800;%30min is 1800sec
                if(TimeElapsed)
                    SessionIndex(NewRequest)=SessionIndex(SelectedRequest);
                    SessionState(NewRequest)=1;%Open This 
                    SelectedRequest=NewRequest;
                else
                    SessionState(find(SessionIndex==SessionIndex(SelectedRequest)))=2;%Closed
                    
                    SessionState(NewRequest)=1;%Open This 
                    SessionNumber=SessionNumber+1;% New Session
                    SessionIndex(NewRequest)=SessionNumber;
                    SelectedRequest=NewRequest;
                end
            else
                SessionState(NewRequest)=1;%Open This 
                SessionNumber=SessionNumber+1;% New Session
                SessionIndex(NewRequest)=SessionNumber;
                SelectedRequest=NewRequest;
            end
        end
    else
        RequestsOfOpenSessions=find(SessionState==1);
            if(numel(RequestsOfOpenSessions)>0)
                SelectedRequest=RequestsOfOpenSessions(find(strcmp(IP(RequestsOfOpenSessions),IP(NewRequest)) + strcmp(UserAgent(RequestsOfOpenSessions),UserAgent(NewRequest)),1,'last'));
                if (numel(SelectedRequest)==0)% There is not a match session
                    SessionState(NewRequest)=1;%Open This 
                    SessionNumber=SessionNumber+1;% New Session
                    SessionIndex(NewRequest)=SessionNumber;
                    SelectedRequest=NewRequest;
                    continue;
                end
                SelectedRequest=find(SessionIndex==SessionIndex(SelectedRequest),1,'last');%It is the last request in a certain session
                TimeElapsed=etime(datevec(DateTime(NewRequest)),datevec(DateTime(SelectedRequest)));
                TimeElapsed=TimeElapsed<=1800;%30min is 1800sec
                if(TimeElapsed)
                    SessionIndex(NewRequest)=SessionIndex(SelectedRequest);
                    SessionState(NewRequest)=1;%Open This
                    SelectedRequest=NewRequest;
                else
                    SessionState(find(SessionIndex==SessionIndex(SelectedRequest)))=2;%Closed
                    
                    SessionState(NewRequest)=1;%Open This 
                    SessionNumber=SessionNumber+1;% New Session
                    SessionIndex(NewRequest)=SessionNumber;
                    SelectedRequest=NewRequest;
                end
            else
                SessionState(NewRequest)=1;%Open This 
                SessionNumber=SessionNumber+1;% New Session
                SessionIndex(NewRequest)=SessionNumber;
                SelectedRequest=NewRequest;
            end
    end
end
end